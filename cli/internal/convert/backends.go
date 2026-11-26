package convert

import (
	"fmt"
	"net/textproto"
	"regexp"
	"strings"
)

// backend translates single terms and knows an engine's boolean syntax.
type backend interface {
	// term renders one term. ok is false when the engine can't express
	// it; note then says why.
	term(t term) (s string, f Fidelity, note string, ok bool)
	andOp() string
	orOp() string
	canOr() bool
	wrap(q string) string
}

var backends = map[string]backend{
	"fofa":    fofa{},
	"shodan":  shodan{},
	"censys":  censys{},
	"zoomeye": zoomeye{},
	"modat":   modat{},
	"urlscan": urlscan{},
	"huntio":  huntio{},
}

// kind says how an engine searches a field.
type kind int

const (
	substring     kind = iota // substring search: contains is exact
	words                     // tokenised or whole-word search: contains is approximate
	exactOnly                 // hashes and numbers: equality only
	rawHeaders                // the value is searched anywhere in the raw header block
	oneHeader                 // Modat: one header by name and value
	fullText                  // Shodan: a quoted phrase in the full banner text
	prefixKeyword             // urlscan: whole value or prefix, indexed in lowercase
	regexKeyword              // urlscan: whole value, prefix or anchored regex, indexed in lowercase
)

type fieldSpec struct {
	name       string
	kind       kind
	regex      bool   // the engine supports regex on this field
	analyzed   bool   // Censys: ":" tokenises this field by subdomain, so contains needs a regex
	unverified bool   // mapping marked † in spec Appendix A
	loose      bool   // the engine field covers more than the taxonomy field, so even equality is approximate
	note       string // known limitation, shown with every query that uses the field
}

// Engines index only part of large bodies (spec section 10, body truncation).
const (
	shodanBodyNote = "shodan does not index all of a large body; a body condition can miss hosts the scanner finds"
	// https://docs.censys.com/docs/platform-host-dataset: host service
	// endpoints index the first 64 KB of a body and the first 2 KB of the
	// header block. The 6 KB figure applies to name-based web properties,
	// which a host.services query does not search.
	censysBodyNote     = "censys indexes the first 64 KB of an http body on a host service; a body condition deeper in the page can miss hosts the scanner finds"
	censysBodyHashNote = "censys hashes the first 64 KB of a body, the rule the whole body; the two differ for bodies over 64 KB"
	censysHeaderNote   = "censys indexes the first 2 KB of a header block; a header beyond that can miss hosts the scanner finds"
	censysModuleNote   = "jarm, ja3s and ja4s need access to the censys Adversary Investigation module"
	urlscanHashNote    = "urlscan's hash matches any response the page loaded, not only this one"
)

var (
	fofaFields = map[string]fieldSpec{
		"http.title":          {name: "title"},
		"http.body":           {name: "body"},
		"http.headers_raw":    {name: "header", kind: rawHeaders},
		"http.headers.server": {name: "server", unverified: true},
		"http.status_code":    {name: "status_code", kind: exactOnly, unverified: true},
		"http.favicon.mmh3":   {name: "icon_hash", kind: exactOnly},
		"tls.cert.subject.cn": {name: "cert.subject.cn"},
		"tls.cert.issuer.cn":  {name: "cert.issuer.cn", unverified: true},
		"tls.jarm":            {name: "jarm", kind: exactOnly},
		"service.banner":      {name: "banner"},
		"service.port":        {name: "port", kind: exactOnly},
	}
	zoomeyeFields = map[string]fieldSpec{
		"http.title":          {name: "title"},
		"http.body":           {name: "http.body"},
		"http.headers_raw":    {name: "http.header", kind: rawHeaders},
		"http.headers.server": {name: "http.header.server"},
		"http.status_code":    {name: "http.header.status_code", kind: exactOnly},
		"http.favicon.mmh3":   {name: "iconhash", kind: exactOnly},
		"http.favicon.md5":    {name: "iconhash", kind: exactOnly},
		"tls.cert.subject.cn": {name: "ssl.cert.subject.cn"},
		"tls.cert.issuer.cn":  {name: "ssl.cert.issuer.cn"},
		"tls.jarm":            {name: "ssl.jarm", kind: exactOnly},
		"tls.ja3s":            {name: "ssl.ja3s", kind: exactOnly},
		"service.banner":      {name: "banner"},
		"service.port":        {name: "port", kind: exactOnly},
	}
	shodanFields = map[string]fieldSpec{
		"http.title":          {name: "http.title", kind: words},
		"http.body":           {name: "http.html", kind: words, note: shodanBodyNote},
		"http.headers_raw":    {kind: fullText},
		"http.status_code":    {name: "http.status", kind: exactOnly},
		"http.favicon.mmh3":   {name: "http.favicon.hash", kind: exactOnly},
		"http.body.mmh3":      {name: "http.html_hash", kind: exactOnly, unverified: true},
		"tls.cert.subject.cn": {name: "ssl.cert.subject.cn", kind: words},
		"tls.cert.issuer.cn":  {name: "ssl.cert.issuer.cn", kind: words},
		"tls.jarm":            {name: "ssl.jarm", kind: exactOnly},
		"tls.ja3s":            {name: "ssl.ja3s", kind: exactOnly},
		"service.banner":      {kind: fullText},
		"service.port":        {name: "port", kind: exactOnly},
	}
	// Censys Platform field names are relative to host.services, because
	// every query is wrapped in host.services: ( … ) to stay on one service
	// (https://docs.censys.com/docs/platform-host-dataset).
	censysFields = map[string]fieldSpec{
		"http.title":          {name: "endpoints.http.html_title", kind: words, regex: true},
		"http.body":           {name: "endpoints.http.body", kind: words, regex: true, note: censysBodyNote},
		"http.headers.server": {name: "server", kind: oneHeader},
		"http.status_code":    {name: "endpoints.http.status_code", kind: exactOnly},
		"http.favicon.md5":    {name: "endpoints.http.favicons.hash_md5", kind: exactOnly},
		"http.favicon.sha256": {name: "endpoints.http.favicons.hash_sha256", kind: exactOnly},
		"http.body.sha256":    {name: "endpoints.http.body_hash_sha256", kind: exactOnly, note: censysBodyHashNote},
		// cert.* under host.services is the service's certificate; the
		// common-name fields use a subdomain analyzer, so ":" matches whole
		// domain labels and a substring search needs a regex.
		"tls.cert.subject.cn": {name: "cert.parsed.subject.common_name", kind: words, regex: true, analyzed: true},
		"tls.cert.issuer.cn":  {name: "cert.parsed.issuer.common_name", kind: words, regex: true, analyzed: true},
		"tls.cert.subject.dn": {name: "cert.parsed.subject_dn", kind: words, regex: true},
		"tls.cert.issuer.dn":  {name: "cert.parsed.issuer_dn", kind: words, regex: true},
		"tls.cert.sha256":     {name: "cert.fingerprint_sha256", kind: exactOnly},
		"tls.cert.sha1":       {name: "cert.fingerprint_sha1", kind: exactOnly},
		"tls.cert.san":        {name: "cert.names", kind: words, regex: true, analyzed: true},
		"tls.jarm":            {name: "jarm.fingerprint", kind: exactOnly, note: censysModuleNote},
		"tls.ja3s":            {name: "tls.ja3s", kind: exactOnly, note: censysModuleNote},
		"tls.ja4s":            {name: "tls.ja4s", kind: exactOnly, note: censysModuleNote},
		"service.banner":      {name: "banner", kind: words, regex: true},
		"service.port":        {name: "port", kind: exactOnly},
	}
	modatFields = map[string]fieldSpec{
		"http.title":          {name: "http.title", regex: true},
		"http.body":           {name: "http.body", kind: words},
		"http.headers_raw":    {name: "http.headers", kind: words},
		"http.status_code":    {name: "http.status_code", kind: exactOnly},
		"http.favicon.mmh3":   {name: "http.files.mmh3", kind: exactOnly},
		"http.favicon.sha256": {name: "http.files.sha256", kind: exactOnly},
		"http.body.mmh3":      {name: "http.body_mmh3", kind: exactOnly, unverified: true},
		"http.body.sha256":    {name: "http.body_sha256", kind: exactOnly},
		"tls.cert.subject.cn": {name: "tls.subject.common_name", regex: true},
		"tls.cert.issuer.cn":  {name: "tls.issuer.common_name", regex: true},
		"tls.cert.sha256":     {name: "tls.fingerprint_sha256", kind: exactOnly},
		"tls.jarm":            {name: "tls.jarm", kind: exactOnly},
		"tls.ja3s":            {name: "tls.ja3s", kind: exactOnly},
		"service.banner":      {name: "banner", kind: words},
		"service.port":        {name: "port", kind: exactOnly},
	}
	// urlscan fields describe the page a browser ended up on. Fields that are
	// missing here have no counterpart: urlscan indexes no body, banner, port,
	// certificate subject or header other than Server.
	urlscanFields = map[string]fieldSpec{
		"http.title":          {name: "page.title.keyword", kind: regexKeyword},
		"http.headers.server": {name: "page.server", kind: words},
		"http.status_code":    {name: "page.status", kind: exactOnly},
		"http.body.sha256":    {name: "hash", kind: exactOnly, loose: true, note: urlscanHashNote},
		"http.favicon.sha256": {name: "hash", kind: exactOnly, loose: true, note: urlscanHashNote},
		"tls.cert.issuer.cn":  {name: "page.tlsIssuer", kind: prefixKeyword},
	}
	// hunt.io fields are columns of its ip.current table, as the portal's
	// schema panel lists them. Text columns are searched with LIKE, the rest
	// with ==. Missing here: JA3S and full text, which have no column, and
	// html.body.hash.murmur3 and protocol.data, whose meaning the schema
	// doesn't pin down (see huntio.term).
	huntioFields = map[string]fieldSpec{
		"http.title":                {name: "html.head.title"},
		"http.body":                 {name: "html.body.content"},
		"http.headers_raw":          {name: "http.headers.bytes.content", kind: rawHeaders},
		"http.headers.server":       {name: "http.headers.server"},
		"http.headers.x-powered-by": {name: "http.headers.x_powered_by"},
		"http.headers.etag":         {name: "http.headers.etag"},
		"http.status_code":          {name: "http.headers.status.code", kind: exactOnly},
		"http.favicon.mmh3":         {name: "favicon.hash.mmh3", kind: exactOnly},
		"http.favicon.md5":          {name: "favicon.hash.md5", kind: exactOnly},
		"http.favicon.sha256":       {name: "favicon.hash.sha256", kind: exactOnly},
		"http.body.sha256":          {name: "html.body.hash.sha256", kind: exactOnly},
		"tls.cert.subject.cn":       {name: "tls.cert.subject.common_name"},
		"tls.cert.issuer.cn":        {name: "tls.cert.issuer.common_name"},
		"tls.cert.sha256":           {name: "tls.cert.hash.sha256", kind: exactOnly},
		"tls.jarm":                  {name: "jarm.fingerprint", kind: exactOnly},
		"service.port":              {name: "service.port", kind: exactOnly},
	}
)

// fieldTables holds every engine's fields. A query on a field marked
// unverified is never exact (see converter.lower).
var fieldTables = map[string]map[string]fieldSpec{
	"fofa":    fofaFields,
	"shodan":  shodanFields,
	"censys":  censysFields,
	"zoomeye": zoomeyeFields,
	"modat":   modatFields,
	"urlscan": urlscanFields,
	"huntio":  huntioFields,
}

// lookup applies the checks every engine shares and finds the field.
// Single headers (http.headers.<name>) map to the engine's header search.
func lookup(engine string, fields map[string]fieldSpec, headerKind kind, t term) (fieldSpec, string, bool) {
	switch t.op {
	case "null", "exists", "gt", "gte", "lt", "lte", "cidr":
		return fieldSpec{}, fmt.Sprintf("%s: %s can't express |%s", describe(t), engine, t.op), false
	}
	if t.hex {
		return fieldSpec{}, fmt.Sprintf("%s: %s can't search hex values", describe(t), engine), false
	}
	if rest, ok := strings.CutPrefix(t.field, "x-"); ok {
		eng, name, _ := strings.Cut(rest, ".")
		if eng != engine {
			return fieldSpec{}, fmt.Sprintf("%s is specific to %s", t.field, eng), false
		}
		return fieldSpec{name: name}, "", true
	}
	if spec, ok := fields[t.field]; ok {
		if spec.loose && t.negated {
			return fieldSpec{}, widenedNote(t, fmt.Sprintf("%s's %s covers more than %s", engine, spec.name, t.field)), false
		}
		note := spec.note
		if spec.unverified {
			note = joinNote(note, fmt.Sprintf("the mapping of %s to %s is not verified against the %s docs yet", t.field, spec.name, engine))
		}
		return spec, note, true
	}
	if name, ok := strings.CutPrefix(t.field, "http.headers."); ok && headerKind != substring {
		if headerKind == rawHeaders {
			// One header is searched as its value in the raw header block.
			return fields["http.headers_raw"], "", true
		}
		return fieldSpec{name: name, kind: headerKind}, "", true
	}
	return fieldSpec{}, fmt.Sprintf("%s has no field for %s", engine, t.field), false
}

func noWildcards(engine string, t term) (string, bool) {
	if t.wild {
		return fmt.Sprintf("%s: %s can't search Sigma wildcards", describe(t), engine), false
	}
	return "", true
}

// widened reports a negated exact, prefix or suffix match that an engine
// can only search as a substring or as words. The looser search finds more
// services, so its negation excludes more: services the rule matches would
// be missing from the query. Backends drop such terms instead, which keeps
// the query a superset (spec section 10).
func widened(t term) bool {
	return t.negated && (t.op == "eq" || t.op == "startswith" || t.op == "endswith")
}

func widenedNote(t term, how string) string {
	return fmt.Sprintf("not %s: %s, which would also exclude services the rule matches", describe(t), how)
}

// caseLost says why an engine's search for a |cased term ignores case, and
// so finds more than the term. It returns "" where the operator the backend
// uses is case-sensitive. The converter then labels the term approximate, or
// drops it under not, as backends do with widened terms.
func caseLost(engine string, t term) string {
	if !t.cased {
		return ""
	}
	switch engine {
	case "fofa", "shodan":
		// No case-sensitive operator.
	case "modat":
		// ==, ~~ and ==~ are case-sensitive. Hashes and numbers are searched
		// with =, and a regex on a header with =~.
		spec, _, _ := lookup(engine, modatFields, oneHeader, t)
		if spec.kind != exactOnly && (spec.kind != oneHeader || t.op != "re") {
			return ""
		}
	case "zoomeye":
		// == on a text field is case-sensitive.
		spec, _, _ := lookup(engine, zoomeyeFields, rawHeaders, t)
		if spec.kind == substring && t.op == "eq" {
			return ""
		}
	case "censys":
		// "=" is case-sensitive and "=~" is too unless the backend adds
		// (?i), which it only does for terms that are not |cased.
		return ""
	case "urlscan":
		return "urlscan indexes values in lowercase, so the search ignores case"
	case "huntio":
		return "" // LIKE and == are case-sensitive
	default:
		return "" // scanner templates match as the rule does
	}
	return fmt.Sprintf("%s searches %q without regard to case", engine, t.value)
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// ---- FOFA ----

type fofa struct{}

func (fofa) andOp() string        { return " && " }
func (fofa) orOp() string         { return " || " }
func (fofa) canOr() bool          { return true }
func (fofa) wrap(q string) string { return q }

func (fofa) term(t term) (string, Fidelity, string, bool) {
	return fofaLike("fofa", fofaFields, t, "==")
}

// fofaLike handles FOFA and ZoomEye, which share =, ==, != and quoting.
func fofaLike(engine string, fields map[string]fieldSpec, t term, exactOp string) (string, Fidelity, string, bool) {
	if note, ok := noWildcards(engine, t); !ok {
		return "", 0, note, false
	}
	if t.field == "" {
		if t.negated {
			return "", 0, fmt.Sprintf("%s can't negate a keyword", engine), false
		}
		return quote(t.value), Approximate, "", true
	}
	spec, note, ok := lookup(engine, fields, rawHeaders, t)
	if !ok {
		return "", 0, note, false
	}
	not := ""
	if t.negated {
		not = "!"
	}
	switch spec.kind {
	case exactOnly:
		if t.op != "eq" {
			return "", 0, fmt.Sprintf("%s: %s only supports equality on %s", describe(t), engine, spec.name), false
		}
		op := "="
		if t.negated {
			op = "!="
		}
		return spec.name + op + quote(t.value), Exact, note, true
	case rawHeaders:
		if t.op == "re" {
			return "", 0, fmt.Sprintf("%s: %s has no regex", describe(t), engine), false
		}
		if t.negated && (t.field != "http.headers_raw" || t.op != "contains") {
			return "", 0, widenedNote(t, fmt.Sprintf("%s can only exclude %q anywhere in the header block", engine, t.value)), false
		}
		q := spec.name + not + "=" + quote(t.value)
		if t.field == "http.headers_raw" {
			// header= is a substring search in the raw block, which is what
			// http.headers_raw|contains means.
			if t.op == "contains" {
				return q, Exact, note, true
			}
			return q, Approximate, joinNote(note, fmt.Sprintf("%s searches the header block for %q as a substring", engine, t.value)), true
		}
		return q, Approximate,
			joinNote(note, fmt.Sprintf("%s searches the whole header block for %q, not one header", engine, t.value)), true
	}
	if widened(t) {
		return "", 0, widenedNote(t, fmt.Sprintf("%s's != excludes every value that contains %q", engine, t.value)), false
	}
	f := Exact
	op := "="
	switch t.op {
	case "contains":
	case "eq":
		op = exactOp
		if engine == "zoomeye" && !t.cased {
			f = Approximate // ZoomEye's == is case-sensitive
		}
	case "startswith", "endswith":
		f = Approximate
	default:
		return "", 0, fmt.Sprintf("%s: %s has no regex", describe(t), engine), false
	}
	if t.negated {
		op = "!="
	}
	return spec.name + op + quote(t.value), f, note, true
}

// ---- ZoomEye ----

type zoomeye struct{}

func (zoomeye) andOp() string        { return " && " }
func (zoomeye) orOp() string         { return " || " }
func (zoomeye) canOr() bool          { return true }
func (zoomeye) wrap(q string) string { return q }

func (zoomeye) term(t term) (string, Fidelity, string, bool) {
	return fofaLike("zoomeye", zoomeyeFields, t, "==")
}

// ---- Shodan ----

type shodan struct{}

func (shodan) andOp() string        { return " " }
func (shodan) orOp() string         { return "" }
func (shodan) canOr() bool          { return false }
func (shodan) wrap(q string) string { return q }

var shodanBare = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func (shodan) term(t term) (string, Fidelity, string, bool) {
	if note, ok := noWildcards("shodan", t); !ok {
		return "", 0, note, false
	}
	if t.op == "re" {
		return "", 0, describe(t) + ": shodan has no regex", false
	}
	if t.field == "" {
		if t.negated {
			return "", 0, "shodan can't negate a keyword", false
		}
		return quote(t.value), Approximate, "", true
	}
	spec, note, ok := lookup("shodan", shodanFields, fullText, t)
	if !ok {
		return "", 0, note, false
	}
	neg := ""
	if t.negated {
		neg = "-"
	}
	switch spec.kind {
	case fullText:
		if t.negated {
			return "", 0, "shodan can't negate a full-text phrase", false
		}
		phrase := t.value
		if strings.HasPrefix(t.field, "http.headers.") {
			phrase = textproto.CanonicalMIMEHeaderKey(spec.name) + ": " + t.value
		}
		return quote(phrase), Approximate, joinNote(note, fmt.Sprintf("shodan searches %s as full text", t.field)), true
	case exactOnly:
		if t.op != "eq" {
			return "", 0, fmt.Sprintf("%s: shodan only supports equality on %s", describe(t), spec.name), false
		}
		v := t.value
		if !shodanBare.MatchString(v) {
			v = quote(v)
		}
		return neg + spec.name + ":" + v, Exact, note, true
	}
	// Text filters match tokens, so every text operator is approximate.
	if widened(t) {
		return "", 0, widenedNote(t, fmt.Sprintf("shodan's -%s excludes %q anywhere in the text", spec.name, t.value)), false
	}
	return neg + spec.name + ":" + quote(t.value), Approximate, note, true
}

// key lets an OR of positive values of one filter become a comma list,
// http.title:"a","b", which Shodan reads as a or b.
func (shodan) key(t term) (string, string) {
	if t.negated || t.field == "" || t.op == "re" || t.wild || t.hex {
		return "", ""
	}
	spec, ok := shodanFields[t.field]
	if !ok {
		return "", ""
	}
	switch spec.kind {
	case words:
		return spec.name, quote(t.value)
	case exactOnly:
		if t.op != "eq" {
			return "", ""
		}
		if shodanBare.MatchString(t.value) {
			return spec.name, t.value
		}
		return spec.name, quote(t.value)
	}
	return "", ""
}

func (shodan) list(field string, values []string) string {
	return field + ":" + strings.Join(values, ",")
}

// ---- Censys Platform ----

type censys struct{}

func (censys) andOp() string        { return " and " }
func (censys) orOp() string         { return " or " }
func (censys) canOr() bool          { return true }
func (censys) wrap(q string) string { return "host.services: (" + q + ")" }

func (censys) term(t term) (string, Fidelity, string, bool) {
	if t.field == "" {
		return "", 0, "censys full-text search can't be nested in host.services", false
	}
	// exists and the numeric comparisons have their own operators on
	// censys; lookup only knows the string ones, so it sees eq.
	probe := t
	switch t.op {
	case "exists", "gt", "gte", "lt", "lte":
		probe.op = "eq"
	}
	spec, note, ok := lookup("censys", censysFields, oneHeader, probe)
	if !ok {
		return "", 0, note, false
	}
	if spec.kind == oneHeader {
		// Header values take "=" and "=~" inside the nested group, and
		// every header search reads the same truncated block.
		spec.regex = true
		note = joinNote(note, censysHeaderNote)
	}
	not := ""
	if t.negated {
		not = "not "
	}

	switch t.op {
	case "exists":
		// ":*" matches any non-zero value. |exists: false is its negation.
		if spec.kind == oneHeader {
			return "", 0, describe(t) + ": censys can't test a single header for presence", false
		}
		if (t.value == "false") != t.negated {
			not = "not "
		} else {
			not = ""
		}
		return not + spec.name + ": *", Exact, note, true
	case "gt", "gte", "lt", "lte":
		if spec.kind != exactOnly {
			return "", 0, fmt.Sprintf("%s: censys compares only numbers, dates and addresses, not %s", describe(t), spec.name), false
		}
		op := map[string]string{"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[t.op]
		// Censys wants integers and dates quoted.
		return not + spec.name + " " + op + " " + quote(t.value), Exact, note, true
	}

	if spec.kind == exactOnly {
		if t.op != "eq" || t.wild {
			return "", 0, fmt.Sprintf("%s: censys only supports equality on %s", describe(t), spec.name), false
		}
		return not + spec.name + " = " + quote(t.value), Exact, note, true
	}
	if !spec.regex {
		return "", 0, describe(t) + ": not supported on censys", false
	}

	re, f, reNote, ok := censysPattern(t)
	if !ok {
		return "", 0, reNote, false
	}
	if spec.kind == oneHeader {
		// One header by name and value, as the regex docs spell it:
		// endpoints.http.headers: (key = "Server" and value =~ "…").
		key := textproto.CanonicalMIMEHeaderKey(spec.name)
		cond := "value =~ " + quote(re)
		headNote := joinNote(note, reNote)
		if t.op == "eq" && t.cased {
			// An exact, case-sensitive value needs no regex.
			cond, f, headNote = "value = "+quote(t.value), Exact, note
		}
		return not + "endpoints.http.headers: (key = " + quote(key) + " and " + cond + ")", f, headNote, true
	}
	if t.op == "eq" && t.cased {
		// "=" is an exact, case-sensitive match on a string field.
		return not + spec.name + " = " + quote(t.value), Exact, note, true
	}
	if t.op == "contains" && !t.cased && !t.wild && !spec.analyzed {
		// ":" is case-insensitive, but it tokenises: it matches the words of
		// the value in order, not an arbitrary substring.
		return not + spec.name + ": " + quote(t.value), Approximate, note, true
	}
	note = joinNote(note, reNote)
	if spec.analyzed {
		note = joinNote(note, fmt.Sprintf("censys tokenises %s by domain label, so the search uses a regex", spec.name))
	}
	// Two layers: the regex, then the double-quoted string, in which
	// Censys wants every backslash of the regex doubled ("\\.").
	return not + spec.name + " =~ " + quote(re), f, note, true
}

// censysPattern builds the regex for a term on a field that supports "=~".
// Censys regex is case-sensitive and unanchored, so a term that is not
// |cased gets the (?i) flag and a positional term gets ^ or $.
func censysPattern(t term) (string, Fidelity, string, bool) {
	flag := "(?i)"
	if t.cased {
		flag = ""
	}
	if t.op == "re" {
		// The rule's regex is RE2 and already says whether it ignores
		// case, so it is passed through as written.
		re := censysRegex(t.raw)
		if !censysAnchorsOK(re) {
			return "", 0, describe(t) + ": censys allows ^ and $ only at the ends of a regex", false
		}
		return re, Approximate, "censys's regex dialect is smaller than RE2", true
	}
	lit := escapeRunes(t.value, censysSpecial)
	if t.wild {
		// Censys dropped * and ? as wildcards outside regex, so a Sigma
		// wildcard becomes its regex equivalent.
		lit = censysWildcard(t.value)
	}
	switch t.op {
	case "eq":
		lit = "^" + lit + "$"
	case "startswith":
		lit = "^" + lit
	case "endswith":
		lit += "$"
	case "contains":
	default:
		return "", 0, describe(t) + ": not supported on censys", false
	}
	return flag + lit, Exact, "", true
}

// censysWildcard turns a value with Sigma wildcards into a regex: * is any
// run of characters, ? is one, and the rest is escaped.
func censysWildcard(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			if strings.ContainsRune(censysSpecial, r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// censysAnchorsOK reports whether every ^ and $ of a regex sits where Censys
// accepts it: ^ as the first character after any flags, $ as the last.
// Elsewhere the query fails. Inside [ ] a ^ negates the class and is fine.
func censysAnchorsOK(re string) bool {
	body := re
	for {
		rest, ok := strings.CutPrefix(body, "(?i)")
		if !ok {
			break
		}
		body = rest
	}
	inClass := false
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '^' && i != 0:
			return false
		case c == '$' && i != len(body)-1:
			return false
		}
	}
	return true
}

// censysSpecial lists the characters the Censys regex docs say to escape
// with a backslash, and | for alternatives.
const censysSpecial = `\.+*?()[]{}|^$":/`

// censysRegex escapes the quotes in a rule's regex that have no backslash
// yet, as Censys asks for.
func censysRegex(re string) string {
	var b strings.Builder
	for i := 0; i < len(re); i++ {
		switch c := re[i]; {
		case c == '\\' && i+1 < len(re):
			b.WriteByte(c)
			i++
			b.WriteByte(re[i])
		case c == '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ---- Modat Magnify ----

type modat struct{}

func (modat) andOp() string        { return " and " }
func (modat) orOp() string         { return " or " }
func (modat) canOr() bool          { return true }
func (modat) wrap(q string) string { return q }

var modatBare = regexp.MustCompile(`^-?[0-9]+$`)

func (modat) term(t term) (string, Fidelity, string, bool) {
	not := ""
	if t.negated {
		not = "not "
	}
	if t.field == "" {
		if t.negated || t.wild {
			return "", 0, "modat can't negate or wildcard a keyword", false
		}
		val, bad, ok := modatValue(t)
		if !ok {
			return "", 0, bad, false
		}
		return quoteRegex(val), Approximate, "modat searches a bare phrase in eleven fields, not only banner, headers and body", true
	}
	spec, note, ok := lookup("modat", modatFields, oneHeader, t)
	if !ok {
		return "", 0, note, false
	}
	val, bad, ok := modatValue(t)
	if !ok {
		return "", 0, bad, false
	}

	switch spec.kind {
	case exactOnly:
		if t.op != "eq" || t.wild {
			return "", 0, fmt.Sprintf("%s: modat only supports equality on %s", describe(t), spec.name), false
		}
		v := t.value
		if !modatBare.MatchString(v) {
			v = quoteRegex(val)
		}
		return not + spec.name + "=" + v, Exact, note, true

	case oneHeader:
		if t.wild {
			return "", 0, describe(t) + ": modat can't search wildcards in a header", false
		}
		key := textproto.CanonicalMIMEHeaderKey(spec.name)
		var cond string
		f := Exact
		switch {
		case t.op == "re":
			cond, f = "value =~ "+quoteRegex(val), Approximate
		case t.cased:
			// Header values have no case-sensitive = or ~; use ==~.
			cond = "value ==~ " + quoteRegex(anchor(t))
		case t.op == "contains":
			cond = "value ~ " + quoteRegex(val)
		case t.op == "eq":
			cond = "value = " + quoteRegex(val)
		default:
			cond = "value =~ " + quoteRegex(anchor(t))
		}
		return not + "http.headers: (key = " + quote(key) + " and " + cond + ")", f, note, true

	case words:
		// Whole-word fields: exact equality works, substring search does not.
		if t.wild || t.op == "re" {
			return "", 0, fmt.Sprintf("%s: modat has no regex or wildcards on %s", describe(t), spec.name), false
		}
		if t.op == "eq" {
			op := "="
			if t.cased {
				op = "=="
			}
			return not + spec.name + op + quoteRegex(val), Exact, note, true
		}
		op := "~"
		if t.cased {
			op = "~~"
		}
		return not + spec.name + op + quoteRegex(val), Approximate,
			joinNote(note, fmt.Sprintf("modat matches whole words on %s", spec.name)), true
	}

	// Substring fields such as http.title.
	if t.wild {
		pattern := val
		switch t.op {
		case "contains":
			pattern = "*" + pattern + "*"
		case "startswith":
			pattern += "*"
		case "endswith":
			pattern = "*" + pattern
		case "re":
			return "", 0, describe(t) + ": wildcards and regex together", false
		}
		op := "="
		if t.cased {
			op = "=="
		}
		return not + spec.name + op + quoteRegex(pattern), Exact, note, true
	}
	switch t.op {
	case "contains":
		op := "~"
		if t.cased {
			op = "~~"
		}
		return not + spec.name + op + quoteRegex(val), Exact, note, true
	case "eq":
		op := "="
		if t.cased {
			op = "=="
		}
		return not + spec.name + op + quoteRegex(val), Exact, note, true
	case "startswith", "endswith", "re":
		if !spec.regex {
			return "", 0, fmt.Sprintf("%s: no regex on %s", describe(t), spec.name), false
		}
		op := "=~"
		if t.cased {
			op = "==~"
		}
		if t.op == "re" {
			return not + spec.name + op + quoteRegex(val), Approximate,
				joinNote(note, "modat's regex dialect is smaller than RE2"), true
		}
		return not + spec.name + op + quoteRegex(anchor(t)), Exact, note, true
	}
	return "", 0, describe(t) + ": not supported on modat", false
}

// anchor turns a literal condition into an anchored regex.
func anchor(t term) string {
	lit := modatLiteral(t.value)
	switch t.op {
	case "eq":
		return "^" + lit + "$"
	case "startswith":
		return "^" + lit
	case "endswith":
		return lit + "$"
	}
	return lit
}

// Modat values have two layers. The outer one is the double-quoted string, in
// which \" is a quote. Modat's examples hand other backslashes on to the
// inner layer, the wildcard pattern ("\*") or the regex ("nginx/1\.(18|20)"),
// but its docs don't say how a backslash itself is written, or whether \\ is
// one backslash or two. So nothing is written with \\ or with a backslash in
// front of a quote, and a value that holds a backslash is not converted.

// modatValue returns a term's value as the inner layer, a Modat pattern or
// regex. It is false, with a note, for a value Modat can't hold.
func modatValue(t term) (val, note string, ok bool) {
	if t.op == "re" {
		val, ok = modatRegex(t.raw)
	} else {
		val, ok = modatPattern(t.raw)
	}
	if !ok {
		note = describe(t) + ": modat does not document how to write a backslash in a value"
	}
	return val, note, ok
}

// modatPattern turns a rule value into a Modat pattern. Both write wildcards
// as * and ? and the literal characters as \* and \?. Any other backslash in
// a rule value is a literal backslash.
func modatPattern(raw string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			if i+1 == len(raw) || (raw[i+1] != '*' && raw[i+1] != '?') {
				return "", false
			}
			b.WriteByte(raw[i])
			i++
		}
		b.WriteByte(raw[i])
	}
	return b.String(), true
}

// modatLiteral turns a text without backslashes into a Modat regex. The
// characters Modat's docs name are escaped as they say. Its regex also has
// Lucene's operators ~ and &, where a quote starts a literal string and #, @,
// < and > can be operators too. These are written as a class of one
// character, ["], which is a literal in every regex dialect and needs no
// backslash.
func modatLiteral(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case strings.ContainsRune(`"~&#@<>`, r):
			b.WriteString("[" + string(r) + "]")
		case strings.ContainsRune(`.+*?()[]{}|^$:/`, r):
			b.WriteString(`\` + string(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// modatRegex rewrites a rule's regex so that no quote has a backslash in
// front: \" and " become ["] outside a character class and " inside one. It
// is false for a regex with an escaped backslash.
func modatRegex(re string) (string, bool) {
	var b strings.Builder
	class := false
	for i := 0; i < len(re); i++ {
		c := re[i]
		switch {
		case c == '\\':
			if i+1 == len(re) || re[i+1] == '\\' {
				return "", false
			}
			i++
			if c = re[i]; c != '"' {
				b.WriteByte('\\')
			}
		case class && strings.HasPrefix(re[i:], "[:") && strings.Contains(re[i:], ":]"):
			// A named class such as [:alpha:] inside a class.
			end := i + strings.Index(re[i:], ":]") + 1
			b.WriteString(re[i:end])
			i, c = end, ']'
		case c == '[' && !class:
			class = true
			// A ] right after [ or [^ is a literal.
			for _, lit := range []byte("^]") {
				if i+1 < len(re) && re[i+1] == lit {
					b.WriteByte(c)
					i++
					c = lit
				}
			}
		case c == ']':
			class = false
		}
		if c == '"' && !class {
			b.WriteString(`["]`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// ---- urlscan.io ----

// urlscan indexes pages a browser loaded for submitted URLs, not services
// found by scanning. Its query syntax is the Elasticsearch query string, and
// every value is indexed in lowercase.
type urlscan struct{}

func (urlscan) andOp() string        { return " AND " }
func (urlscan) orOp() string         { return " OR " }
func (urlscan) canOr() bool          { return true }
func (urlscan) wrap(q string) string { return q }
func (urlscan) groupNegation()       {}

func (urlscan) notes() []string {
	return []string{"urlscan indexes pages a browser loaded from submitted URLs, after redirects, not first responses from IP:port"}
}

var urlscanBare = regexp.MustCompile(`^[a-z0-9]+$`)

func (urlscan) term(t term) (string, Fidelity, string, bool) {
	switch {
	case t.field == "":
		return "", 0, describe(t) + ": urlscan has no full-text search of banners, headers and bodies", false
	case t.field == "http.body":
		return "", 0, describe(t) + ": urlscan doesn't index the HTML body; text.content holds only the visible text", false
	case t.field == "http.headers_raw" || strings.HasPrefix(t.field, "http.headers.") && t.field != "http.headers.server":
		return "", 0, describe(t) + ": urlscan indexes no response header except Server", false
	}
	spec, note, ok := lookup("urlscan", urlscanFields, substring, t)
	if !ok {
		return "", 0, note, false
	}
	not := ""
	if t.negated {
		not = "NOT "
	}
	f := Exact
	if spec.loose {
		f = Approximate
	}
	v := strings.ToLower(t.value)

	switch spec.kind {
	case exactOnly:
		if t.op != "eq" || t.wild {
			return "", 0, fmt.Sprintf("%s: urlscan only supports equality on %s", describe(t), spec.name), false
		}
		if !urlscanBare.MatchString(v) {
			v = quote(v)
		}
		return not + spec.name + ":" + v, f, note, true

	case words:
		// Text fields: a quoted phrase matches a sequence of words.
		if t.wild || t.op == "re" {
			return "", 0, fmt.Sprintf("%s: urlscan has no regex or wildcards on %s", describe(t), spec.name), false
		}
		if widened(t) {
			return "", 0, widenedNote(t, fmt.Sprintf("NOT %s excludes %q anywhere in the value", spec.name, t.value)), false
		}
		return not + spec.name + ":" + quote(t.value), Approximate,
			joinNote(note, fmt.Sprintf("urlscan matches words on %s", spec.name)), true

	case prefixKeyword:
		if !t.wild {
			switch t.op {
			case "eq":
				return not + spec.name + ":" + quote(v), f, note, true
			case "startswith":
				return not + spec.name + ":" + luceneEscape(v) + "*", f, note, true
			}
		}
		return "", 0, fmt.Sprintf("%s: urlscan only searches whole values and prefixes on %s", describe(t), spec.name), false

	case regexKeyword:
		if t.op == "re" {
			return "", 0, describe(t) + ": urlscan's regex dialect (Lucene, anchored, lowercase values) differs from RE2", false
		}
		if t.op == "eq" && !t.wild {
			return not + spec.name + ":" + quote(v), f, note, true
		}
		// Lucene regexes are anchored at both ends.
		re := luceneRegex(t)
		switch t.op {
		case "contains":
			re = ".*" + re + ".*"
		case "startswith":
			re += ".*"
		case "endswith":
			re = ".*" + re
		}
		return not + spec.name + ":/" + re + "/", f, note, true
	}
	return "", 0, describe(t) + ": not supported on urlscan", false
}

// probeTerm converts the body hash of a custom probe, which fetches one file.
// urlscan stores the SHA-256 of every file a page loads, so hash: finds the
// pages that loaded it. Nothing else a custom probe sees is indexed.
func (urlscan) probeTerm(t term) (string, Fidelity, string, bool) {
	if t.field != "http.body.sha256" || t.op != "eq" || t.negated || t.wild || t.hex {
		return "", 0, fmt.Sprintf("%s uses the custom probe %q; urlscan only searches the body SHA-256 of files a page loaded", describe(t), t.probe), false
	}
	v := strings.ToLower(t.value)
	if !urlscanBare.MatchString(v) {
		v = quote(v)
	}
	return "hash:" + v, Approximate,
		fmt.Sprintf("urlscan finds the file of probe %q only on pages that loaded it", t.probe), true
}

// luceneRegex turns a value into a Lucene regex on lowercase text: literal
// characters escaped, Sigma's * and ? as .* and .
func luceneRegex(t term) string {
	if !t.wild {
		return luceneLiteral(strings.ToLower(t.value))
	}
	var b strings.Builder
	raw := []rune(strings.ToLower(t.raw))
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '\\' && i+1 < len(raw) && strings.ContainsRune(`*?\`, raw[i+1]):
			b.WriteString(luceneLiteral(string(raw[i+1])))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(luceneLiteral(string(c)))
		}
	}
	return b.String()
}

// luceneLiteral escapes a text for a /regex/ in the query string. A backslash
// becomes the class [\\]: after \\ the query string's lexer reads a slash as
// \/, part of the regex, also when it is the slash that ends the regex.
func luceneLiteral(s string) string {
	return strings.ReplaceAll(regexLiteral(s), `\\`, `[\\]`)
}

// luceneEscape escapes the query-string reserved characters and spaces in a
// bare term, for prefix searches such as page.tlsIssuer:gts\ ca*.
func luceneEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`+-=&|><!(){}[]^"~*?:\/ `, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---- hunt.io ----

// huntio writes HuntSQL for hunt.io's ip.current table. A row there is one
// IP with its services nested under it, and same_port( … ) keeps every
// condition on one service, so the query asks for that. In the portal on
// 2026-11-26: LIKE is SQL's, anchored at both ends with % and _ as
// wildcards; LIKE and == are case-sensitive; RLIKE is anchored at both ends.
type huntio struct{}

func (huntio) andOp() string { return " AND " }
func (huntio) orOp() string  { return " OR " }
func (huntio) canOr() bool   { return true }

func (huntio) wrap(q string) string {
	return "SELECT ip, service.port FROM ip.current WHERE same_port(" + q + ")"
}

func (huntio) notes() []string {
	return []string{"huntio searches the ip.current rows of the last 30 days unless the query adds a timestamp condition"}
}

// huntioInts are the integer columns, compared with a bare number.
var huntioInts = map[string]bool{"http.status_code": true, "http.favicon.mmh3": true, "service.port": true}

var huntioNumber = regexp.MustCompile(`^-?[0-9]+$`)

const huntioCaseNote = "huntio's LIKE and == are case-sensitive, so the query misses values that differ from the rule's only in case"

func (huntio) term(t term) (string, Fidelity, string, bool) {
	switch {
	case t.field == "":
		return "", 0, describe(t) + ": huntio has no full-text search", false
	case t.field == "http.body.mmh3":
		return "", 0, describe(t) + ": huntio does not document which Murmur3 variant html.body.hash.murmur3 holds", false
	case t.field == "service.banner":
		return "", 0, describe(t) + ": huntio does not document which probe's answer protocol.data holds", false
	case t.op == "re":
		return "", 0, describe(t) + ": huntio's RLIKE is anchored at both ends and its regex dialect is not documented", false
	}
	spec, note, ok := lookup("huntio", huntioFields, rawHeaders, t)
	if !ok {
		return "", 0, note, false
	}
	not := func(s string) string {
		if t.negated {
			return "NOT (" + s + ")"
		}
		return s
	}

	if spec.kind == exactOnly {
		if t.op != "eq" || t.wild {
			return "", 0, fmt.Sprintf("%s: huntio only supports equality on %s", describe(t), spec.name), false
		}
		v := t.value
		if huntioInts[t.field] {
			if !huntioNumber.MatchString(v) {
				return "", 0, fmt.Sprintf("%s: huntio's %s holds integers", describe(t), spec.name), false
			}
		} else if v, ok = huntioQuote(v); !ok {
			return "", 0, huntioQuoteNote(t), false
		}
		return not(spec.name + " == " + v), Exact, note, true
	}

	// Text columns, and the header block for headers without a column.
	f := Exact
	if !t.cased {
		f, note = Approximate, joinNote(note, huntioCaseNote)
	}
	op := t.op
	if spec.kind == rawHeaders {
		if t.field != "http.headers_raw" || op != "contains" {
			if t.negated {
				return "", 0, widenedNote(t, fmt.Sprintf("huntio can only exclude %q anywhere in the header block", t.value)), false
			}
			how := fmt.Sprintf("huntio searches the whole header block for %q, not one header", t.value)
			if t.field == "http.headers_raw" {
				how = fmt.Sprintf("huntio searches the header block for %q as a substring", t.value)
			}
			f, note = Approximate, joinNote(note, how)
		}
		op = "contains"
	}
	if op == "eq" && !t.wild {
		// == compares the literal value, % and _ included.
		v, ok := huntioQuote(t.value)
		if !ok {
			return "", 0, huntioQuoteNote(t), false
		}
		return not(spec.name + " == " + v), f, note, true
	}
	pattern, loose := huntioLike(t.raw)
	if loose {
		if t.negated {
			return "", 0, widenedNote(t, "LIKE reads its % and _ as wildcards"), false
		}
		f, note = Approximate, joinNote(note, fmt.Sprintf("LIKE reads the %% and _ in %q as wildcards", t.value))
	}
	switch op {
	case "contains":
		pattern = "%" + pattern + "%"
	case "startswith":
		pattern += "%"
	case "endswith":
		pattern = "%" + pattern
	}
	v, ok := huntioQuote(pattern)
	if !ok {
		return "", 0, huntioQuoteNote(t), false
	}
	return not(spec.name + " LIKE " + v), f, note, true
}

// huntioLike turns a rule value into a LIKE pattern: Sigma's * and ? become
// % and _, and \*, \? and \\ the characters themselves. loose reports a %
// or _ in the value, which LIKE reads as a wildcard; HuntSQL documents no
// escape for them.
func huntioLike(raw string) (pattern string, loose bool) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '\\' && i+1 < len(raw) && strings.IndexByte(`*?\`, raw[i+1]) >= 0:
			i++
			b.WriteByte(raw[i])
		case c == '*':
			b.WriteByte('%')
		case c == '?':
			b.WriteByte('_')
		default:
			loose = loose || c == '%' || c == '_'
			b.WriteByte(c)
		}
	}
	return b.String(), loose
}

// huntioQuote writes a value in single quotes, or in double quotes when it
// holds a single quote. HuntSQL documents both kinds of quotes but no
// escapes, so a value with a backslash, or with both kinds of quotes, can't
// be written.
func huntioQuote(s string) (string, bool) {
	switch {
	case strings.Contains(s, `\`):
		return "", false
	case !strings.Contains(s, "'"):
		return "'" + s + "'", true
	case !strings.Contains(s, `"`):
		return `"` + s + `"`, true
	}
	return "", false
}

func huntioQuoteNote(t term) string {
	return describe(t) + ": huntio documents no way to write a backslash, or both kinds of quotes, in a value"
}
