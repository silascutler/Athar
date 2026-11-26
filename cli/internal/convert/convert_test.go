package convert

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Athar-HQ/Athar/cli/internal/eval"
	"github.com/Athar-HQ/Athar/cli/internal/rule"
)

func ruleFrom(t *testing.T, detection string) *rule.Rule {
	t.Helper()
	src := "title: t\ndetection:\n"
	for _, line := range strings.Split(strings.TrimRight(detection, "\n"), "\n") {
		src += "  " + line + "\n"
	}
	src += "probes:\n  api: { protocol: http, request: { path: /api } }\n"
	r, err := rule.Parse([]byte(src), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := eval.Compile(r); err != nil {
		t.Fatalf("rule does not compile: %v", err)
	}
	return r
}

// Fixed copies of the rules in spec section 10, so edits to the live rules
// don't change what these tests check.
const (
	specFamily = `
selection_title:
  http.title|contains: 'Autonomous Penetration Testing Console'
selection_route:
  http.body|contains: '/function/tasks'
condition: selection_title and selection_route
`
	specVariant = `
selection_title:
  http.title|contains: 'Autonomous Penetration Testing Console'
selection_route:
  http.body|contains: '/function/tasks'
selection_brand:
  http.title|startswith: 'ARTEX'
selection_icon:
  http.favicon.mmh3: -576220750
condition: selection_title and selection_route and (selection_brand or selection_icon)
`
	specBasicAuth = `
selection_realm:
  http.headers.www-authenticate: 'Basic realm="ARTEX", charset="UTF-8"'
condition: selection_realm
`
	localizedFamily = `
selection_title:
  http.title|contains:
    - '自主渗透测试控制台'
    - '자율 침투 테스트 콘솔'
    - 'Autonomous Penetration Testing Console'
condition: selection_title
`
)

type want struct {
	query string
	fid   Fidelity
}

func check(t *testing.T, r *rule.Rule, cases map[string]want) {
	t.Helper()
	for engine, w := range cases {
		res, err := Convert(r, engine)
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		if res.Query != w.query || res.Fidelity != w.fid {
			t.Errorf("%s:\n got  [%s] %s\nwant [%s] %s\nnotes: %v", engine, res.Fidelity, res.Query, w.fid, w.query, res.Notes)
		}
	}
}

// The family and variant conversions in spec section 10.
func TestSpecExamples(t *testing.T) {
	check(t, ruleFrom(t, specFamily), map[string]want{
		"fofa":    {`title="Autonomous Penetration Testing Console" && body="/function/tasks"`, Exact},
		"shodan":  {`http.title:"Autonomous Penetration Testing Console" http.html:"/function/tasks"`, Approximate},
		"censys":  {`host.services: (endpoints.http.html_title: "Autonomous Penetration Testing Console" and endpoints.http.body: "/function/tasks")`, Approximate},
		"zoomeye": {`title="Autonomous Penetration Testing Console" && http.body="/function/tasks"`, Exact},
		"modat":   {`http.title~"Autonomous Penetration Testing Console" and http.body~"/function/tasks"`, Approximate},
		"urlscan": {`page.title.keyword:/.*autonomous penetration testing console.*/`, Superset},
		"huntio":  {`SELECT ip, service.port FROM ip.current WHERE same_port(html.head.title LIKE '%Autonomous Penetration Testing Console%' AND html.body.content LIKE '%/function/tasks%')`, Approximate},
	})
	check(t, ruleFrom(t, specVariant), map[string]want{
		"fofa":    {`title="Autonomous Penetration Testing Console" && body="/function/tasks" && (title="ARTEX" || icon_hash="-576220750")`, Approximate},
		"shodan":  {`http.title:"Autonomous Penetration Testing Console" http.html:"/function/tasks"`, Superset},
		"censys":  {`host.services: (endpoints.http.html_title: "Autonomous Penetration Testing Console" and endpoints.http.body: "/function/tasks")`, Superset},
		"zoomeye": {`title="Autonomous Penetration Testing Console" && http.body="/function/tasks" && (title="ARTEX" || iconhash="-576220750")`, Approximate},
		"modat":   {`http.title~"Autonomous Penetration Testing Console" and http.body~"/function/tasks" and (http.title=~"^ARTEX" or http.files.mmh3=-576220750)`, Approximate},
		"urlscan": {`page.title.keyword:/.*autonomous penetration testing console.*/`, Superset},
		"huntio":  {`SELECT ip, service.port FROM ip.current WHERE same_port(html.head.title LIKE '%Autonomous Penetration Testing Console%' AND html.body.content LIKE '%/function/tasks%' AND (html.head.title LIKE 'ARTEX%' OR favicon.hash.mmh3 == -576220750))`, Approximate},
	})
	check(t, ruleFrom(t, specBasicAuth), map[string]want{
		"modat":   {`http.headers: (key = "Www-Authenticate" and value = "Basic realm=\"ARTEX\", charset=\"UTF-8\"")`, Exact},
		"fofa":    {`header="Basic realm=\"ARTEX\", charset=\"UTF-8\""`, Approximate},
		"zoomeye": {`http.header="Basic realm=\"ARTEX\", charset=\"UTF-8\""`, Approximate},
		"censys":  {`host.services: (endpoints.http.headers: (key = "Www-Authenticate" and value =~ "(?i)^Basic realm=\\\"ARTEX\\\", charset=\\\"UTF-8\\\"$"))`, Exact},
		"urlscan": {"", Unsupported},
		"huntio":  {`SELECT ip, service.port FROM ip.current WHERE same_port(http.headers.bytes.content LIKE '%Basic realm="ARTEX", charset="UTF-8"%')`, Approximate},
	})
}

// Negations are pushed down to single conditions; a filter that can't be
// expressed is dropped, which widens the query (the superset rule).
func TestNegationAndSuperset(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.title|contains: Console
filter:
  http.favicon.mmh3: 123
condition: sel and not filter
`)
	check(t, r, map[string]want{
		"fofa":    {`title="Console" && icon_hash!="123"`, Exact},
		"shodan":  {`http.title:"Console" -http.favicon.hash:123`, Approximate},
		"modat":   {`http.title~"Console" and not http.files.mmh3=123`, Exact},
		"censys":  {`host.services: (endpoints.http.html_title: "Console")`, Superset},
		"zoomeye": {`title="Console" && iconhash!="123"`, Exact},
		"urlscan": {`page.title.keyword:/.*console.*/`, Superset},
		"huntio":  {`SELECT ip, service.port FROM ip.current WHERE same_port(html.head.title LIKE '%Console%' AND NOT (favicon.hash.mmh3 == 123))`, Approximate},
	})

	// not (a or b) becomes not a and not b.
	r = ruleFrom(t, `
sel:
  http.title|contains: Console
a:
  http.body|contains: x
b:
  http.body|contains: y
condition: sel and not (a or b)
`)
	check(t, r, map[string]want{
		"fofa":  {`title="Console" && body!="x" && body!="y"`, Exact},
		"modat": {`http.title~"Console" and not http.body~"x" and not http.body~"y"`, Approximate},
	})

	// not (a and b) becomes not a or not b.
	r = ruleFrom(t, `
sel:
  http.title|contains: Console
pair:
  http.body|contains: x
  http.headers_raw|contains: y
condition: sel and not pair
`)
	check(t, r, map[string]want{
		"fofa": {`title="Console" && (body!="x" || header!="y")`, Exact},
	})

	// header= on FOFA and ZoomEye searches the raw block, so headers_raw
	// converts exactly; one named header is only approximate.
	r = ruleFrom(t, `
sel:
  http.title|contains: Console
proxy:
  http.headers_raw|contains: nginx
condition: sel and not proxy
`)
	check(t, r, map[string]want{
		"fofa":    {`title="Console" && header!="nginx"`, Exact},
		"zoomeye": {`title="Console" && http.header!="nginx"`, Exact},
	})
	r = ruleFrom(t, "sel:\n  http.headers.x-powered-by|contains: Express\ncondition: sel\n")
	if res, _ := Convert(r, "fofa"); res.Fidelity != Approximate || !strings.Contains(strings.Join(res.Notes, " "), "not one header") {
		t.Errorf("got %+v", res)
	}
}

func TestDroppedParts(t *testing.T) {
	// A custom-probe selection is never in an engine's index.
	r := ruleFrom(t, `
sel:
  http.title|contains: Console
api:
  probe: api
  http.body|contains: '"version"'
condition: sel and api
`)
	res, _ := Convert(r, "fofa")
	if res.Query != `title="Console"` || res.Fidelity != Superset || !strings.Contains(strings.Join(res.Notes, " "), "custom probe") {
		t.Errorf("got %+v", res)
	}

	// A rule that is only a regex is unsupported where there is no regex.
	r = ruleFrom(t, "sel:\n  http.title|re: '^AR(TEX|GOS)'\ncondition: sel\n")
	for _, engine := range []string{"fofa", "shodan", "zoomeye"} {
		if res, _ := Convert(r, engine); res.Fidelity != Unsupported || res.Query != "" {
			t.Errorf("%s: got %+v", engine, res)
		}
	}
	if res, _ := Convert(r, "modat"); res.Query != `http.title=~"^AR(TEX|GOS)"` || res.Fidelity != Approximate {
		t.Errorf("modat: got %+v", res)
	}

	// An OR on Shodan is dropped, leaving the rest.
	r = ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.body|contains: y\nc:\n  service.port: 443\ncondition: (a or b) and c\n")
	if res, _ := Convert(r, "shodan"); res.Query != "port:443" || res.Fidelity != Superset {
		t.Errorf("shodan: got %+v", res)
	}
}

func TestOperatorsAndEscaping(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.title: 'Say "hi"'
  tls.cert.subject.cn|endswith: .example.org
condition: sel
`)
	check(t, r, map[string]want{
		"fofa":  {`title=="Say \"hi\"" && cert.subject.cn=".example.org"`, Approximate},
		"modat": {`http.title="Say \"hi\"" and tls.subject.common_name=~"\.example\.org$"`, Exact},
		// Censys "=" is case-sensitive, so a case-insensitive exact match is
		// an anchored regex; a common name is tokenised by domain label, so
		// a suffix search needs a regex too.
		"censys": {`host.services: (endpoints.http.html_title =~ "(?i)^Say \\\"hi\\\"$" and cert.parsed.subject.common_name =~ "(?i)\\.example\\.org$")`, Exact},
	})

	// A quote or a backslash in a value never ends the quoted string.
	for _, c := range []struct {
		detection string
		want      map[string]want
	}{
		// Modat: a quote in a regex is the class ["], written [\"].
		{`http.headers.www-authenticate|startswith: 'Basic realm="ARTEX"'`, map[string]want{
			"modat": {`http.headers: (key = "Www-Authenticate" and value =~ "^Basic realm=[\"]ARTEX[\"]")`, Exact},
		}},
		{`http.headers.www-authenticate|re: '^Basic realm="[^"]+", a\"b$'`, map[string]want{
			"modat": {`http.headers: (key = "Www-Authenticate" and value =~ "^Basic realm=[\"][^\"]+[\"], a[\"]b$")`, Approximate},
		}},
		// Censys: the regex escapes the quote, the string doubles the backslash.
		{`http.title|re: 'foo\"bar'`, map[string]want{
			"censys": {`host.services: (endpoints.http.html_title =~ "foo\\\"bar")`, Approximate},
			"modat":  {`http.title=~"foo[\"]bar"`, Approximate},
		}},
		{`http.title|re: '^\d+ "x"$'`, map[string]want{
			"censys": {`host.services: (endpoints.http.html_title =~ "^\\d+ \\\"x\\\"$")`, Approximate},
			"modat":  {`http.title=~"^\d+ [\"]x[\"]$"`, Approximate},
		}},
		// Only regex operators are escaped: no \= or \-.
		{`tls.cert.subject.cn|startswith: 'a=b-c,d.e@f'`, map[string]want{
			"censys": {`host.services: (cert.parsed.subject.common_name =~ "(?i)^a=b-c,d\\.e@f")`, Exact},
			"modat":  {`tls.subject.common_name=~"^a=b-c,d\.e[@]f"`, Exact},
		}},
		// Modat has no documented way to write a backslash, so the value is
		// dropped; a literal * or ? keeps its backslash.
		{`http.title|endswith: 'abc*\'`, map[string]want{
			"modat":   {"", Unsupported},
			"urlscan": {`page.title.keyword:/.*abc.*[\\]/`, Exact},
		}},
		{`http.title|contains: 'C:\\Users'`, map[string]want{
			"modat":   {"", Unsupported},
			"fofa":    {`title="C:\\Users"`, Exact},
			"censys":  {`host.services: (endpoints.http.html_title: "C:\\Users")`, Approximate},
			"urlscan": {`page.title.keyword:/.*c\:[\\]users.*/`, Exact},
		}},
		{`http.title|contains: 'a\*b "c" \?'`, map[string]want{
			"modat": {`http.title~"a\*b \"c\" \?"`, Exact},
		}},
		{`http.title: 'a\*b "c" d*'`, map[string]want{
			"modat": {`http.title="a\*b \"c\" d*"`, Exact},
		}},
		// A line break can't be written in a one-line query.
		{`http.headers_raw|contains: "Server: x\r\nX-Y: z"`, map[string]want{
			"fofa": {"", Unsupported}, "zoomeye": {"", Unsupported}, "shodan": {"", Unsupported}, "modat": {"", Unsupported},
		}},
	} {
		check(t, ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n"), c.want)
	}
	res, _ := Convert(ruleFrom(t, "sel:\n  http.title|endswith: 'abc*\\'\ncondition: sel\n"), "modat")
	if !strings.Contains(strings.Join(res.Notes, " "), "backslash") {
		t.Errorf("modat: notes don't explain the dropped backslash: %v", res.Notes)
	}

	// Values lists: OR by default, AND with |all.
	r = ruleFrom(t, "sel:\n  http.title|contains|all: [a, b]\nalt:\n  http.title|contains: [c, d]\ncondition: sel or alt\n")
	check(t, r, map[string]want{
		"fofa": {`(title="a" && title="b") || title="c" || title="d"`, Exact},
	})

	// Sigma wildcards: Modat has them, the others drop the condition.
	r = ruleFrom(t, "sel:\n  http.title: 'AR*X Console'\nport:\n  service.port: 443\ncondition: sel and port\n")
	check(t, r, map[string]want{
		"modat": {`http.title="AR*X Console" and port=443`, Exact},
		"fofa":  {`port="443"`, Superset},
	})

	// Engine-specific fields only reach their own engine.
	r = ruleFrom(t, "sel:\n  x-fofa.app: ARTEX\nport:\n  service.port: 8443\ncondition: sel and port\n")
	check(t, r, map[string]want{
		"fofa":    {`app=="ARTEX" && port="8443"`, Exact},
		"zoomeye": {`port="8443"`, Superset},
	})
}

// A value YAML reads as a number reaches the engines as the author wrote it.
func TestValuesAsWritten(t *testing.T) {
	r := ruleFrom(t, "sel:\n  http.title: 0100\n  http.body|contains: 2.0\n  tls.cert.subject.cn|contains: 1_000\nicon:\n  http.favicon.mmh3: -576220750\ncondition: sel and icon\n")
	check(t, r, map[string]want{
		"fofa":  {`body="2.0" && title=="0100" && cert.subject.cn="1_000" && icon_hash="-576220750"`, Exact},
		"modat": {`http.body~"2.0" and http.title="0100" and tls.subject.common_name~"1_000" and http.files.mmh3=-576220750`, Approximate},
	})
	// Only the values matter here, not the form of the matcher around them.
	tmpl := nucleiFor(t, "sel:\n  http.title: 0100\n  http.body|contains: 2.0\ncondition: sel\n")
	wantIn(t, tmpl, `"2.0")`)
	wantIn(t, tmpl, `== "0100"`)
	wantData(t, nseFor(t, "sel:\n  http.title: 0100\n  service.banner|hex|startswith: 0016\ncondition: sel\n"),
		`{f = "http.title", m = "eq", v = "0100"}`,
		`{f = "service.banner", m = "startswith", v = "\x00\x16", c = true}`)
}

func TestUnknownEngine(t *testing.T) {
	if _, err := Convert(ruleFrom(t, specFamily), "bing"); err == nil {
		t.Error("want error for unknown engine")
	}
}

// Shodan has no OR, but lists several values of one filter with commas:
// http.title:"a","b" finds a or b (checked on shodan.io, 2026-11-25).
func TestShodanValueLists(t *testing.T) {
	check(t, ruleFrom(t, localizedFamily), map[string]want{
		"shodan":  {`http.title:"自主渗透测试控制台","자율 침투 테스트 콘솔","Autonomous Penetration Testing Console"`, Approximate},
		"fofa":    {`title="自主渗透测试控制台" || title="자율 침투 테스트 콘솔" || title="Autonomous Penetration Testing Console"`, Exact},
		"urlscan": {`page.title.keyword:/.*自主渗透测试控制台.*/ OR page.title.keyword:/.*자율 침투 테스트 콘솔.*/ OR page.title.keyword:/.*autonomous penetration testing console.*/`, Exact},
	})
	// Different filters still can't be ORed on Shodan.
	r := ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.favicon.mmh3: 1\nport:\n  service.port: 443\ncondition: (a or b) and port\n")
	check(t, r, map[string]want{"shodan": {"port:443", Superset}})
	// A negated value is not listed.
	r = ruleFrom(t, "a:\n  http.title|contains: x\nb:\n  http.title|contains: y\nport:\n  service.port: 443\ncondition: port and (a or not b)\n")
	check(t, r, map[string]want{"shodan": {"port:443", Superset}})
}

// urlscan searches lowercase values, anchors its regexes, and reads
// a OR NOT b as a AND NOT b, so a negation inside OR gets its own group.
func TestUrlscan(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.status_code: 200
brand:
  http.title|startswith: 'ARTEX'
login:
  http.title: 'Login / Admin'
condition: sel and (brand or not login)
`)
	check(t, r, map[string]want{
		"urlscan": {`page.status:200 AND (page.title.keyword:/artex.*/ OR (NOT page.title.keyword:"login / admin"))`, Exact},
	})

	cases := []struct {
		detection string
		want      want
	}{
		// Sigma wildcards become regex wildcards; escaped ones stay literal.
		{`http.title: 'AR*X C?nsole \*'`, want{`page.title.keyword:/ar.*x c.nsole \*/`, Exact}},
		{`http.title|endswith: '.io'`, want{`page.title.keyword:/.*\.io/`, Exact}},
		// Everything is indexed in lowercase, so cased only approximates.
		{`http.title|contains|cased: ARTEX`, want{`page.title.keyword:/.*artex.*/`, Approximate}},
		// hash covers every response of the page load.
		{`http.favicon.sha256: ABCDEF01`, want{`hash:abcdef01`, Approximate}},
		{`http.headers.server|contains: 'nginx'`, want{`page.server:"nginx"`, Approximate}},
		{`tls.cert.issuer.cn|startswith: 'GTS CA'`, want{`page.tlsIssuer:gts\ ca*`, Exact}},
		{`tls.cert.issuer.cn|contains: 'GTS'`, want{"", Unsupported}},
		{`http.title|re: '^AR(TEX|GOS)'`, want{"", Unsupported}},
		{`http.body|contains: '/function/tasks'`, want{"", Unsupported}},
		{`http.headers.www-authenticate|contains: 'ARTEX'`, want{"", Unsupported}},
		{`service.port: 8787`, want{"", Unsupported}},
	}
	for _, c := range cases {
		check(t, ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n"), map[string]want{"urlscan": c.want})
	}

	// A custom probe's body hash is the hash of the file it fetches, which
	// urlscan stores for every file a page loads. Other custom probe fields
	// are dropped, and other engines drop the whole selection.
	r = ruleFrom(t, `
css:
  probe: api
  http.body.sha256: FF75F55E
other:
  probe: api
  http.body.sha256: 0a1b2c3d
condition: css or other
`)
	check(t, r, map[string]want{
		"urlscan": {`hash:ff75f55e OR hash:0a1b2c3d`, Approximate},
		"fofa":    {"", Unsupported},
	})
	r = ruleFrom(t, "css:\n  probe: api\n  http.status_code: 200\n  http.body.sha256: ff75\ncondition: css\n")
	check(t, r, map[string]want{"urlscan": {`hash:ff75`, Superset}})
	r = ruleFrom(t, "title:\n  http.title|contains: Console\ncss:\n  probe: api\n  http.body.sha256: ff75\ncondition: title and not css\n")
	check(t, r, map[string]want{"urlscan": {`page.title.keyword:/.*console.*/`, Superset}})

	// Every query says what urlscan's records are.
	res, _ := Convert(ruleFrom(t, specFamily), "urlscan")
	if !strings.Contains(strings.Join(res.Notes, " "), "after redirects") {
		t.Errorf("missing the page-load note: %v", res.Notes)
	}
}

// huntioHead starts every hunt.io query.
const huntioHead = "SELECT ip, service.port FROM ip.current WHERE same_port("

// hunt.io's LIKE and == are case-sensitive, so only |cased terms convert
// exactly. LIKE is anchored, with % and _ as wildcards; RLIKE is anchored too
// and its dialect undocumented, so |re is dropped (checked in the portal,
// 2026-11-26).
func TestHuntio(t *testing.T) {
	cases := []struct {
		detection string
		want      want
	}{
		{`http.title|contains|cased: ARTEX`, want{`html.head.title LIKE '%ARTEX%'`, Exact}},
		{`http.title|startswith|cased: ARTEX`, want{`html.head.title LIKE 'ARTEX%'`, Exact}},
		{`http.title|endswith: ' Console'`, want{`html.head.title LIKE '% Console'`, Approximate}},
		{`http.title|cased: 'Say "hi"'`, want{`html.head.title == 'Say "hi"'`, Exact}},
		{`http.title|cased: "it's"`, want{`html.head.title == "it's"`, Exact}},
		// Sigma wildcards become LIKE wildcards; escaped ones stay literal.
		{`http.title|cased: 'AR*X C?nsole'`, want{`html.head.title LIKE 'AR%X C_nsole'`, Exact}},
		{`http.title|cased: 'AR\*X'`, want{`html.head.title == 'AR*X'`, Exact}},
		{`http.title|contains|cased: '\*'`, want{`html.head.title LIKE '%*%'`, Exact}},
		// A % or _ in the value is a wildcard to LIKE, but not to ==.
		{`http.title|contains|cased: '100%'`, want{`html.head.title LIKE '%100%%'`, Approximate}},
		{`http.title|cased: 'a_b'`, want{`html.head.title == 'a_b'`, Exact}},
		// No documented escapes.
		{`http.title|contains: 'C:\\Users'`, want{"", Unsupported}},
		{`http.title|contains: 'it''s "x"'`, want{"", Unsupported}},
		{`http.title|re: '^AR(TEX|GOS)'`, want{"", Unsupported}},
		{`http.body|contains|cased: '/function/tasks'`, want{`html.body.content LIKE '%/function/tasks%'`, Exact}},
		{`http.headers.server|contains|cased: nginx`, want{`http.headers.server LIKE '%nginx%'`, Exact}},
		{`http.headers.x-powered-by|cased: Express`, want{`http.headers.x_powered_by == 'Express'`, Exact}},
		{`http.headers_raw|contains|cased: X-Havoc`, want{`http.headers.bytes.content LIKE '%X-Havoc%'`, Exact}},
		{`http.headers_raw|startswith|cased: 'HTTP/1.1 200'`, want{`http.headers.bytes.content LIKE '%HTTP/1.1 200%'`, Approximate}},
		{`http.headers.www-authenticate|cased: ARTEX`, want{`http.headers.bytes.content LIKE '%ARTEX%'`, Approximate}},
		{`http.status_code: 200`, want{`http.headers.status.code == 200`, Exact}},
		{`http.favicon.mmh3: -576220750`, want{`favicon.hash.mmh3 == -576220750`, Exact}},
		{`http.favicon.sha256: abcdef01`, want{`favicon.hash.sha256 == 'abcdef01'`, Exact}},
		{`tls.cert.sha256: abcdef01`, want{`tls.cert.hash.sha256 == 'abcdef01'`, Exact}},
		{`tls.cert.issuer.cn|cased: 'PentAGI CA'`, want{`tls.cert.issuer.common_name == 'PentAGI CA'`, Exact}},
		{`tls.jarm: abcdef01`, want{`jarm.fingerprint == 'abcdef01'`, Exact}},
		{`service.port: 8787`, want{`service.port == 8787`, Exact}},
		{`x-huntio.html.head.meta.generator|contains|cased: WordPress`, want{`html.head.meta.generator LIKE '%WordPress%'`, Exact}},
		{`tls.jarm|contains: abc`, want{"", Unsupported}},
		{`tls.ja3s: abc`, want{"", Unsupported}},
		{`service.banner|contains: SSH`, want{"", Unsupported}},
		{`http.body.mmh3: 123`, want{"", Unsupported}},
		{`- ARTEX`, want{"", Unsupported}},
	}
	for _, c := range cases {
		w := c.want
		if w.query != "" {
			w.query = huntioHead + w.query + ")"
		}
		check(t, ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n"), map[string]want{"huntio": w})
	}

	// Negations become NOT ( … ), inside OR too.
	r := ruleFrom(t, `
sel:
  http.title|contains|cased: Console
brand:
  http.title|startswith|cased: ARTEX
filter:
  http.title|contains|cased: ScopeWeaver
condition: sel and (brand or not filter)
`)
	check(t, r, map[string]want{
		"huntio": {huntioHead + `html.head.title LIKE '%Console%' AND (html.head.title LIKE 'ARTEX%' OR NOT (html.head.title LIKE '%ScopeWeaver%')))`, Exact},
	})
	// A negated LIKE with a literal % or _, or one header searched in the
	// whole block, would exclude services the rule matches, so it is dropped.
	for _, filter := range []string{`http.title|contains|cased: 'a_b'`, `http.headers.www-authenticate|contains|cased: ARTEX`} {
		r = ruleFrom(t, "sel:\n  http.title|contains|cased: Console\nfilter:\n  "+filter+"\ncondition: sel and not filter\n")
		check(t, r, map[string]want{"huntio": {huntioHead + `html.head.title LIKE '%Console%')`, Superset}})
		res, _ := Convert(r, "huntio")
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, "would also exclude services the rule matches") {
			t.Errorf("%s: notes don't explain the dropped filter: %v", filter, res.Notes)
		}
	}

	// Every query says which rows it searches, and an uncased one why it is
	// approximate.
	res, _ := Convert(ruleFrom(t, specFamily), "huntio")
	if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, "last 30 days") || !strings.Contains(notes, "case-sensitive") {
		t.Errorf("missing notes: %v", res.Notes)
	}
}

// Every rule in the repository converts for every engine without error.
func TestRepositoryRules(t *testing.T) {
	files, err := rule.Files([]string{"../../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		r, err := rule.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, engine := range Engines {
			res, err := Convert(r, engine)
			if err != nil {
				t.Errorf("%s %s: %v", f, engine, err)
			}
			if (res.Query == "") != (res.Fidelity == Unsupported) {
				t.Errorf("%s %s: query %q with fidelity %s", f, engine, res.Query, res.Fidelity)
			}
		}
	}
}

// Under not, a looser engine operator excludes more than the rule does, so
// the query would miss services the rule matches. A negated exact, prefix or
// suffix match that an engine can only search as a substring or as words is
// dropped instead, and the query stays a superset (spec section 10).
func TestNegatedLooserOperators(t *testing.T) {
	r := ruleFrom(t, `
sel:
  http.title|contains: Console
filter_prefix:
  http.title|startswith: ARTEX
filter_exact:
  http.title: Admin Console
filter_header:
  http.headers.x-powered-by|contains: Express
filter_server:
  http.headers.server|contains: nginx
condition: sel and not 1 of filter_*
`)
	check(t, r, map[string]want{
		"fofa":    {`title="Console" && server!="nginx"`, Superset},
		"zoomeye": {`title="Console" && http.header.server!="nginx"`, Superset},
		"shodan":  {`http.title:"Console"`, Superset},
		"modat":   {`http.title~"Console" and not http.title="Admin Console" and not http.headers: (key = "X-Powered-By" and value ~ "Express") and not http.title=~"^ARTEX" and not http.headers: (key = "Server" and value ~ "nginx")`, Exact},
	})
	for _, engine := range []string{"fofa", "zoomeye", "shodan"} {
		res, _ := Convert(r, engine)
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, `not http.title|startswith "ARTEX"`) || !strings.Contains(notes, "would also exclude services the rule matches") {
			t.Errorf("%s: notes don't explain the dropped filter: %v", engine, res.Notes)
		}
	}

	// A negated exact match on one header: FOFA's server and urlscan's
	// page.server are searched as substring or words.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.headers.server: nginx\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":    {`title="Console"`, Superset},
		"urlscan": {`page.title.keyword:/.*console.*/`, Superset},
	})

	// A negated substring search still converts.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.title|contains: ARTEX\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":   {`title="Console" && title!="ARTEX"`, Exact},
		"shodan": {`http.title:"Console" -http.title:"ARTEX"`, Approximate},
	})
}

// target.tls is not part of an engine query, so the query also returns
// services the rule can't match: an exact result becomes a superset, and
// every result says so. A positive certificate condition already limits the
// query to TLS services.
func TestTargetTLS(t *testing.T) {
	const required = "target.tls: required is not part of the query; it also returns plaintext services"
	const none = "target.tls: none is not part of the query; it also returns TLS services"
	title := "selection:\n  http.title: 'Console'\ncondition: selection\n"
	cert := "selection:\n  tls.cert.subject.cn: 'acme'\ncondition: selection\n"
	for _, c := range []struct {
		name, detection, tls, engine, query string
		fid                                 Fidelity
		note                                string
	}{
		{"auto", title, "auto", "fofa", `title=="Console"`, Exact, ""},
		{"required", title, "required", "fofa", `title=="Console"`, Superset, required},
		{"none", title, "none", "fofa", `title=="Console"`, Superset, none},
		{"required, zoomeye", title, "required", "zoomeye", `title=="Console"`, Approximate, required},
		{"required, modat", title, "required", "modat", `http.title="Console"`, Superset, required},
		{"required, already approximate", title, "required", "shodan", `http.title:"Console"`, Approximate, required},
		{"none, already approximate", "selection:\n  http.title|contains: 'Console'\ncondition: selection\n",
			"none", "censys", `host.services: (endpoints.http.html_title: "Console")`, Approximate, none},
		{"none, censys exact", title, "none", "censys", `host.services: (endpoints.http.html_title =~ "(?i)^Console$")`, Superset, none},
		{"required, urlscan", title, "required", "urlscan", `page.title.keyword:"console"`, Superset, required},
		{"required, already superset", "selection:\n  http.title: 'Console'\n  service.banner|contains: 'x-y'\ncondition: selection\n",
			"required", "urlscan", `page.title.keyword:"console"`, Superset, required},
		{"required, huntio", title, "required", "huntio", huntioHead + `html.head.title == 'Console')`, Approximate, required},
		{"required, huntio, cased", "selection:\n  http.title|cased: 'Console'\ncondition: selection\n",
			"required", "huntio", huntioHead + `html.head.title == 'Console')`, Superset, required},
		{"required, certificate", cert, "required", "fofa", `cert.subject.cn=="acme"`, Exact, ""},
		{"none, certificate", cert, "none", "fofa", `cert.subject.cn=="acme"`, Superset, none},
		{"required, title and certificate", "selection:\n  http.title: 'Console'\n  tls.cert.subject.cn: 'acme'\ncondition: selection\n",
			"required", "fofa", `title=="Console" && cert.subject.cn=="acme"`, Exact, ""},
		{"required, title or certificate", "a:\n  http.title: 'Console'\nb:\n  tls.cert.subject.cn: 'acme'\ncondition: a or b\n",
			"required", "fofa", `title=="Console" || cert.subject.cn=="acme"`, Superset, required},
		{"required, certificate names", "selection:\n  tls.cert.subject.cn|contains: ['acme', 'panel']\ncondition: selection\n",
			"required", "shodan", `ssl.cert.subject.cn:"acme","panel"`, Approximate, ""},
		{"required, negated certificate", "a:\n  http.title: 'Console'\nb:\n  tls.cert.subject.cn|contains: 'acme'\ncondition: a and not b\n",
			"required", "fofa", `title=="Console" && cert.subject.cn!="acme"`, Superset, required},
	} {
		r := ruleFrom(t, c.detection)
		r.Target.TLS = c.tls
		res, err := Convert(r, c.engine)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Query != c.query || res.Fidelity != c.fid {
			t.Errorf("%s:\n got  [%s] %s\nwant [%s] %s\nnotes: %v", c.name, res.Fidelity, res.Query, c.fid, c.query, res.Notes)
		}
		noted := false
		for _, n := range res.Notes {
			noted = noted || strings.HasPrefix(n, "target.tls")
			if strings.HasPrefix(n, "target.tls") && n != c.note {
				t.Errorf("%s: note %q, want %q", c.name, n, c.note)
			}
		}
		if noted != (c.note != "") {
			t.Errorf("%s: notes %q, want %q", c.name, res.Notes, c.note)
		}
	}

	// Nothing to qualify when there is no query.
	r := ruleFrom(t, "selection:\n  service.banner|re: '^x'\ncondition: selection\n")
	r.Target.TLS = "required"
	if res, _ := Convert(r, "shodan"); res.Fidelity != Unsupported || strings.Contains(strings.Join(res.Notes, " "), "target.tls") {
		t.Errorf("unsupported: [%s] %v", res.Fidelity, res.Notes)
	}
}

// Values with quotes, backslashes and line breaks must stay inside their
// quotes on every engine, and what the engine reads back must be the value.
func TestHostileValuesStayQuoted(t *testing.T) {
	// Values as written in a rule: \\ is one backslash, and so is a single \.
	raws := []string{
		`"`, `a"b`, `Basic realm="ARTEX"`, `a'b`, "a`b",
		`\\`, `a\\`, `a\`, `a\b`, `\"`, `a\"b`, `a\\"b`, `a\\\"b`, `"\\`,
		`a/b`, `a\/b`, `a\\/`, "a\nb", "a\r\nb\\",
	}
	fields := []string{
		"", "http.title", "http.body", "http.headers_raw", "http.headers.x-test", "http.headers.server",
		"tls.cert.subject.cn", "tls.cert.issuer.cn", "service.banner",
	}
	mods := []string{"", "|contains", "|startswith", "|endswith", "|cased", "|contains|cased", "|startswith|cased", "|endswith|cased"}
	converted := map[string]int{}
	for _, raw := range raws {
		value, _ := unwildcard(raw)
		y, _ := json.Marshal(raw)
		for _, field := range fields {
			for _, mod := range mods {
				detection := "sel:\n  " + field + mod + ": " + string(y) + "\ncondition: sel\n"
				if field == "" {
					if mod != "" {
						continue
					}
					detection = "sel:\n  - " + string(y) + "\ncondition: sel\n"
				}
				op := strings.TrimSuffix(strings.TrimPrefix(mod, "|"), "|cased")
				r := ruleFrom(t, detection)
				for _, engine := range Engines {
					res, err := Convert(r, engine)
					if err != nil {
						t.Fatalf("%s: %v", engine, err)
					}
					if res.Query == "" {
						continue
					}
					converted[engine]++
					if msg := checkLiteral(engine, res.Query, op, value, value); msg != "" {
						t.Errorf("%s %s%s %q:\n  %s\n  %s", engine, field, mod, raw, res.Query, msg)
					}
				}
			}
		}
	}
	for _, engine := range Engines {
		if converted[engine] == 0 {
			t.Errorf("%s: no value converted", engine)
		}
	}

	// Regular expressions, with a text each one matches.
	regexes := [][2]string{
		{`foo\"bar`, `foo"bar`},
		{`a"b`, `a"b`},
		{`^x[^"]+"$`, `xy"`},
		{`^x[[:alpha:]"]+$`, `xy"`},
		{`[]"]"`, `""`},
		{`a\\b`, `a\b`},
		{`a\\"b`, `a\"b`},
		{`a\\`, `a\`},
		{`a/b\.c`, `a/b.c`},
		{`\d+\.\d"`, `1.2"`},
	}
	for _, re := range regexes {
		y, _ := json.Marshal(re[0])
		for _, field := range []string{"http.title", "http.headers.x-test", "tls.cert.subject.cn", "service.banner"} {
			for _, mod := range []string{"|re", "|re|cased"} {
				r := ruleFrom(t, "sel:\n  "+field+mod+": "+string(y)+"\ncondition: sel\n")
				for _, engine := range Engines {
					res, _ := Convert(r, engine)
					if res.Query == "" {
						continue
					}
					if msg := checkLiteral(engine, res.Query, "re", re[0], re[1]); msg != "" {
						t.Errorf("%s %s%s %q:\n  %s\n  %s", engine, field, mod, re[0], res.Query, msg)
					}
				}
			}
		}
	}
}

var literalHead = regexp.MustCompile(`^(value |[A-Za-z_.]+)? ?(=~|==~|==|=|~~|~|:)? ?$`)

// checkLiteral reads a one-term query as the engine does: first the quoting
// of the value, then, for a regex, the regex itself. It returns what is wrong
// with the query, or "". op is the rule's operator, value the rule's value
// and sample a text the value matches.
func checkLiteral(engine, q, op, value, sample string) string {
	if strings.ContainsFunc(q, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return "control character in the query"
	}
	switch engine {
	case "huntio":
		return checkHuntio(q, op, value, sample)
	case "censys":
		inner, ok := strings.CutPrefix(q, "host.services: (")
		if !ok || !strings.HasSuffix(inner, ")") {
			return "not wrapped in host.services: ( )"
		}
		q = strings.TrimSuffix(inner, ")")
		if in, ok := strings.CutPrefix(strings.Replace(q, `"Server"`, `"X-Test"`, 1), `endpoints.http.headers: (key = "X-Test" and value `); ok {
			if !strings.HasSuffix(in, ")") {
				return "the header group is not closed"
			}
			q = "value " + strings.TrimSuffix(in, ")")
		}
	case "modat":
		if inner, ok := strings.CutPrefix(strings.Replace(q, `"Server"`, `"X-Test"`, 1), `http.headers: (key = "X-Test" and value `); ok {
			if !strings.HasSuffix(inner, ")") {
				return "the header group is not closed"
			}
			q = "value " + strings.TrimSuffix(inner, ")")
		}
	}
	var (
		i       = strings.Index(q, `"`)
		unquote = unquotePairs
		isRegex bool
	)
	switch engine {
	case "modat":
		unquote = unquoteModat
	case "urlscan":
		i = strings.Index(q, ":") + 1
		switch {
		case strings.HasPrefix(q[i:], "/"):
			unquote, isRegex = unquoteSlashes, true
		case !strings.HasPrefix(q[i:], `"`):
			unquote = unquoteBare
		}
		value, sample = strings.ToLower(value), strings.ToLower(sample)
	}
	if i < 0 {
		return "no quoted value"
	}
	head := strings.TrimSpace(q[:i])
	if !literalHead.MatchString(head) {
		return "unexpected text in front of the value: " + head
	}
	got, rest, ok := unquote(q[i:])
	if !ok {
		return "the value's quotes are not closed, or it has an escape the engine does not document"
	}
	if rest != "" {
		return "text after the value: " + rest
	}
	if !isRegex && !strings.HasSuffix(head, "=~") {
		if engine == "urlscan" {
			got = strings.ToLower(got) // page.server is a text field
		}
		if got != value && got != "X-Test: "+value && got != "Server: "+value {
			return "the engine reads the value " + got
		}
		return ""
	}
	flags := "(?s)"
	if engine == "modat" && !strings.HasSuffix(head, "==~") {
		flags = "(?is)" // =~ ignores case
	}
	if engine == "urlscan" {
		got = "^(?:" + got + ")$" // Lucene anchors a regex at both ends
	}
	re, err := regexp.Compile(flags + got)
	if err != nil {
		return "the engine reads the regex " + got + ": " + err.Error()
	}
	return checkMatches(re, got, op, sample)
}

// checkMatches tries a regex an engine reads on texts that the rule's
// operator matches, and on texts it doesn't.
func checkMatches(re *regexp.Regexp, got, op, sample string) string {
	texts := map[string][2][]string{ // operator: texts that match, texts that don't
		"":           {{sample}, {"zz" + sample, sample + "zz"}},
		"cased":      {{sample}, {"zz" + sample, sample + "zz"}},
		"contains":   {{"zz" + sample + "zz"}, nil},
		"startswith": {{sample + "zz"}, {"zz" + sample}},
		"endswith":   {{"zz" + sample}, {sample + "zz"}},
		"re":         {{sample}, nil},
	}[op]
	for _, s := range texts[0] {
		if !re.MatchString(s) {
			return "the engine reads the regex " + got + ", which does not match " + s
		}
	}
	for _, s := range texts[1] {
		if re.MatchString(s) {
			return "the engine reads the regex " + got + ", which matches " + s
		}
	}
	return ""
}

var huntioQuery = regexp.MustCompile(`^SELECT ip, service\.port FROM ip\.current WHERE same_port\(([a-z_.]+) (LIKE|==) (.*)\)$`)

// checkHuntio reads a one-term hunt.io query: a value in single or double
// quotes, with no escapes, compared with == or LIKE. A LIKE pattern is
// anchored at both ends, with % and _ as wildcards; the header block is
// searched for the value anywhere.
func checkHuntio(q, op, value, sample string) string {
	m := huntioQuery.FindStringSubmatch(q)
	if m == nil {
		return "not one column compared inside same_port( )"
	}
	v := m[3]
	if len(v) < 2 || (v[0] != '\'' && v[0] != '"') || v[len(v)-1] != v[0] || strings.IndexByte(v[1:len(v)-1], v[0]) >= 0 {
		return "the value's quotes are not closed, or it holds its own quote"
	}
	got := v[1 : len(v)-1]
	if strings.Contains(got, `\`) {
		return "a backslash, for which HuntSQL documents no meaning"
	}
	if m[2] == "==" {
		if got != value {
			return "the engine reads the value " + got
		}
		return ""
	}
	if m[1] == "http.headers.bytes.content" {
		op = "contains"
	}
	var b strings.Builder
	for _, r := range got {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re := regexp.MustCompile("(?s)^" + b.String() + "$")
	return checkMatches(re, got, op, sample)
}

// unquotePairs reads a double-quoted value in which \\ is a backslash and \"
// a quote, as on FOFA, ZoomEye, Shodan, Censys and in an Elasticsearch
// query string. Any other backslash is an error.
func unquotePairs(s string) (val, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return b.String(), s[i+1:], true
		case '\\':
			if i++; i == len(s) || (s[i] != '\\' && s[i] != '"') {
				return "", "", false
			}
		}
		b.WriteByte(s[i])
	}
	return "", "", false
}

// unquoteModat reads a double-quoted Modat value. Modat documents \" for a
// quote and hands \. and \* on to the regex or wildcard search; it does not
// say what \\ is. So \\ is an error, and so is a backslash in front of the
// closing quote, which is read as \".
func unquoteModat(s string) (val, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '"':
			return b.String(), s[i+1:], true
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '\\':
			return "", "", false
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '"':
			i++
		}
		b.WriteByte(s[i])
	}
	return "", "", false
}

// unquoteSlashes reads a /regex/ of the Elasticsearch query string. Its lexer
// takes \/ for a slash inside the regex and the longest text that ends in a
// slash, so the regex must end at the first slash that has no backslash in
// front: /a\\/ OR b:/c/ would be read as one regex.
func unquoteSlashes(s string) (val, rest string, ok bool) {
	for i := 1; i < len(s); i++ {
		if s[i] == '/' && s[i-1] != '\\' {
			return s[1:i], s[i+1:], true
		}
	}
	return "", "", false
}

// unquoteBare reads an unquoted prefix term of the Elasticsearch query
// string, such as gts\ ca*: reserved characters and spaces need a backslash.
func unquoteBare(s string) (val, rest string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '*':
			return b.String(), s[i+1:], true
		case s[i] == '\\' && i+1 < len(s):
			i++
		case strings.ContainsRune("+-=&|><!(){}[]^\"~?:/ ", rune(s[i])):
			return "", "", false
		}
		b.WriteByte(s[i])
	}
	return "", "", false
}

const unverifiedNote = "is not verified against the"

// Fields marked † in spec Appendix A are not checked against the engine's
// documentation. A query that uses one is approximate at best and says so.
func TestUnverifiedFields(t *testing.T) {
	cases := []struct {
		engine, detection, query string
	}{
		{"fofa", `http.headers.server|contains: nginx`, `server="nginx"`},
		{"fofa", `http.status_code: 200`, `status_code="200"`},
		{"fofa", `tls.cert.issuer.cn|contains: 'PentAGI CA'`, `cert.issuer.cn="PentAGI CA"`},
		{"shodan", `http.body.mmh3: 123`, `http.html_hash:123`},
		{"modat", `http.body.mmh3: 123`, `http.body_mmh3=123`},
	}
	for _, c := range cases {
		r := ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n")
		check(t, r, map[string]want{c.engine: {c.query, Approximate}})
		res, _ := Convert(r, c.engine)
		if !strings.Contains(strings.Join(res.Notes, " "), unverifiedNote+" "+c.engine+" docs") {
			t.Errorf("%s %s: no note that the field is unverified: %v", c.engine, c.detection, res.Notes)
		}
	}

	// Fields whose meaning on the engine is not recorded are not converted:
	// FOFA's body_hash (algorithm undocumented, docs/decisions.md), Shodan's
	// ssl.cert.fingerprint (hash not recorded) and Censys keywords, which
	// can't be nested in host.services.
	dropped := []struct{ engine, detection string }{
		{"fofa", "http.body.mmh3: 123"},
		{"shodan", "tls.cert.sha256: " + strings.Repeat("ab", 32)},
		{"censys", "- ARTEX"},
		{"huntio", "http.body.mmh3: 123"},
		{"huntio", "service.banner|contains: SSH"},
	}
	for _, c := range dropped {
		r := ruleFrom(t, "sel:\n  "+c.detection+"\ncondition: sel\n")
		check(t, r, map[string]want{c.engine: {"", Unsupported}})
	}
}

// appendixRows gives a condition for every row of spec Appendix A.
var appendixRows = map[string]string{
	"`http.title`":          "http.title: x",
	"`http.body`":           "http.body: x",
	"`http.headers.server`": "http.headers.server: x",
	"other headers":         "http.headers.x-athar: x",
	"`http.status_code`":    "http.status_code: 200",
	"`http.favicon.mmh3`":   "http.favicon.mmh3: 123",
	"`http.favicon.md5`":    "http.favicon.md5: " + strings.Repeat("ab", 16),
	"`http.favicon.sha256`": "http.favicon.sha256: " + strings.Repeat("ab", 32),
	"`http.body.mmh3`":      "http.body.mmh3: 123",
	"`http.body.sha256`":    "http.body.sha256: " + strings.Repeat("ab", 32),
	"`tls.cert.subject.cn`": "tls.cert.subject.cn: x",
	"`tls.cert.issuer.cn`":  "tls.cert.issuer.cn: x",
	"`tls.cert.subject.dn`": "tls.cert.subject.dn: x",
	"`tls.cert.issuer.dn`":  "tls.cert.issuer.dn: x",
	"`tls.cert.san`":        "tls.cert.san: x",
	"`tls.cert.sha256`":     "tls.cert.sha256: " + strings.Repeat("ab", 32),
	"`tls.cert.sha1`":       "tls.cert.sha1: " + strings.Repeat("ab", 20),
	"`tls.jarm`":            "tls.jarm: " + strings.Repeat("ab", 31),
	"`tls.ja3s`":            "tls.ja3s: " + strings.Repeat("ab", 16),
	"`tls.ja4s`":            "tls.ja4s: t130200_1303_a56c5b993250",
	"`service.banner`":      "service.banner: x",
	"`service.port`":        "service.port: 443",
	"`keywords`":            "- x",
}

// Spec Appendix A and the backends agree. A cell that starts with a dash or
// says "not converted" is a field no query uses; a cell marked † is a field
// the query uses with the unverified note and never as exact; every other
// cell is a field the query uses without that note.
func TestAppendixAMatchesBackends(t *testing.T) {
	spec, err := os.ReadFile("../../../spec/athar-spec.md")
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(spec), "## Appendix A: Engine field mapping")
	if !ok {
		t.Fatal("spec has no Appendix A")
	}
	seen := map[string]bool{}   // rows found in the table
	marked := map[string]bool{} // engine and field of the † cells
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		detection, ok := appendixRows[cells[0]]
		if !ok {
			continue
		}
		if len(cells) != len(Engines)+1 {
			t.Fatalf("row %s has %d engine cells, want %d", cells[0], len(cells)-1, len(Engines))
		}
		seen[cells[0]] = true
		r := ruleFrom(t, "sel:\n  "+detection+"\ncondition: sel\n")
		for i, engine := range Engines {
			cell := cells[i+1]
			res, err := Convert(r, engine)
			if err != nil {
				t.Fatal(err)
			}
			noted := strings.Contains(strings.Join(res.Notes, " "), unverifiedNote)
			unverified := strings.Contains(cell, "†")
			switch {
			case strings.HasPrefix(cell, "—") || strings.Contains(cell, "not converted"):
				if res.Query != "" {
					t.Errorf("%s on %s: Appendix A says %q, but convert writes %s", cells[0], engine, cell, res.Query)
				}
				continue
			case res.Query == "":
				t.Errorf("%s on %s: Appendix A says %q, but convert writes no query: %v", cells[0], engine, cell, res.Notes)
			case unverified && (!noted || res.Fidelity == Exact):
				t.Errorf("%s on %s: Appendix A marks %q with †, but convert gives [%s] %s, notes %v", cells[0], engine, cell, res.Fidelity, res.Query, res.Notes)
			case !unverified && noted:
				t.Errorf("%s on %s: convert calls the field unverified, but Appendix A has no † on %q", cells[0], engine, cell)
			}
			if unverified {
				marked[engine+" "+strings.Trim(cells[0], "`")] = true
			}
		}
	}
	for row := range appendixRows {
		if !seen[row] {
			t.Errorf("Appendix A has no row %s", row)
		}
	}
	// Every field a backend marks as unverified has a † cell.
	for engine, fields := range fieldTables {
		for field, spec := range fields {
			if spec.unverified && !marked[engine+" "+field] {
				t.Errorf("%s: %s is unverified in backends.go but has no † cell in Appendix A", engine, field)
			}
		}
	}
}

// An engine search that ignores case finds more than a |cased term. Under
// not it would exclude services the rule matches, so the term is dropped;
// case-sensitive operators (Modat's ~~ and ==, Censys = and =~) stay.
func TestNegatedCasedTerms(t *testing.T) {
	r := ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.title|contains|cased: ARTEX\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":    {`title="Console"`, Superset},
		"zoomeye": {`title="Console"`, Superset},
		"shodan":  {`http.title:"Console"`, Superset},
		// Censys regex is case-sensitive, so a |cased filter keeps its meaning.
		"censys":  {`host.services: (endpoints.http.html_title: "Console" and not endpoints.http.html_title =~ "ARTEX")`, Approximate},
		"urlscan": {`page.title.keyword:/.*console.*/`, Superset},
		"modat":   {`http.title~"Console" and not http.title~~"ARTEX"`, Exact},
		"huntio":  {`SELECT ip, service.port FROM ip.current WHERE same_port(html.head.title LIKE '%Console%' AND NOT (html.head.title LIKE '%ARTEX%'))`, Approximate},
	})
	for _, engine := range []string{"fofa", "zoomeye", "shodan", "urlscan"} {
		res, _ := Convert(r, engine)
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, `not http.title|contains "ARTEX"`) || !strings.Contains(notes, "case") || !strings.Contains(notes, "would also exclude services the rule matches") {
			t.Errorf("%s: notes don't explain the dropped filter: %v", engine, res.Notes)
		}
	}

	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.headers_raw|contains|cased: Nginx\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":    {`title="Console"`, Superset},
		"zoomeye": {`title="Console"`, Superset},
	})

	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.title|cased: ARTEX\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"censys": {`host.services: (endpoints.http.html_title: "Console" and not endpoints.http.html_title = "ARTEX")`, Approximate},
		"modat":  {`http.title~"Console" and not http.title=="ARTEX"`, Exact},
	})

	// Censys regex is case-sensitive by default, so a |cased prefix filter
	// is written without (?i) and keeps the rule's meaning under not.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.title|startswith|cased: ARTEX\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"censys": {`host.services: (endpoints.http.html_title: "Console" and not endpoints.http.html_title =~ "^ARTEX")`, Approximate},
		"modat":  {`http.title~"Console" and not http.title==~"^ARTEX"`, Exact},
	})
	// Without |cased the regex carries (?i), which matches the rule.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.title|startswith: ARTEX\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"censys": {`host.services: (endpoints.http.html_title: "Console" and not endpoints.http.html_title =~ "(?i)^ARTEX")`, Approximate},
	})
}

// A positive |cased term on an operator that ignores case over-matches, so
// it is approximate, with a note.
func TestCasedTerms(t *testing.T) {
	r := ruleFrom(t, "sel:\n  http.title|contains|cased: ARTEX\ncondition: sel\n")
	check(t, r, map[string]want{
		"fofa":    {`title="ARTEX"`, Approximate},
		"zoomeye": {`title="ARTEX"`, Approximate},
		"shodan":  {`http.title:"ARTEX"`, Approximate},
		// Censys searches a |cased substring as a case-sensitive regex.
		"censys":  {`host.services: (endpoints.http.html_title =~ "ARTEX")`, Exact},
		"urlscan": {`page.title.keyword:/.*artex.*/`, Approximate},
		"modat":   {`http.title~~"ARTEX"`, Exact},
		"huntio":  {`SELECT ip, service.port FROM ip.current WHERE same_port(html.head.title LIKE '%ARTEX%')`, Exact},
	})
	for _, engine := range []string{"fofa", "zoomeye", "shodan", "urlscan"} {
		res, _ := Convert(r, engine)
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, "case") {
			t.Errorf("%s: no note on the lost |cased: %v", engine, res.Notes)
		}
	}

	// ZoomEye's == and Censys's = are case-sensitive.
	r = ruleFrom(t, "sel:\n  http.title|cased: ARTEX\ncondition: sel\n")
	check(t, r, map[string]want{
		"fofa":    {`title=="ARTEX"`, Approximate},
		"zoomeye": {`title=="ARTEX"`, Exact},
		"censys":  {`host.services: (endpoints.http.html_title = "ARTEX")`, Exact},
		"modat":   {`http.title=="ARTEX"`, Exact},
	})

	// Hashes are searched with =, which only Censys matches by case.
	r = ruleFrom(t, "sel:\n  tls.jarm|cased: ab12\ncondition: sel\n")
	check(t, r, map[string]want{
		"zoomeye": {`ssl.jarm="ab12"`, Approximate},
		"modat":   {`tls.jarm="ab12"`, Approximate},
		"censys":  {`host.services: (jarm.fingerprint = "ab12")`, Exact},
	})
}

// A field the engine maps loosely matches more than the taxonomy field, so
// its negation would exclude services the rule matches and is dropped.
func TestNegatedLooseFields(t *testing.T) {
	for _, field := range []string{"http.body.sha256", "http.favicon.sha256"} {
		r := ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  "+field+": ABCDEF01\ncondition: sel and not filter\n")
		check(t, r, map[string]want{"urlscan": {`page.title.keyword:/.*console.*/`, Superset}})
		res, _ := Convert(r, "urlscan")
		if notes := strings.Join(res.Notes, " "); !strings.Contains(notes, "not "+field) || !strings.Contains(notes, "would also exclude services the rule matches") {
			t.Errorf("urlscan: notes don't explain the dropped filter: %v", res.Notes)
		}
	}

	// Modat has a field for the body hash alone, so the filter stays.
	r := ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.body.sha256: abcdef01\ncondition: sel and not filter\n")
	check(t, r, map[string]want{"modat": {`http.title~"Console" and not http.body_sha256="abcdef01"`, Exact}})

	// No backend negates a loose field.
	for engine, fields := range map[string]map[string]fieldSpec{
		"fofa": fofaFields, "shodan": shodanFields, "censys": censysFields,
		"zoomeye": zoomeyeFields, "modat": modatFields, "urlscan": urlscanFields,
		"huntio": huntioFields,
	} {
		for field, spec := range fields {
			if !spec.loose {
				continue
			}
			if s, _, _, ok := backends[engine].term(term{field: field, op: "eq", value: "ab12", raw: "ab12", probe: "default", negated: true}); ok {
				t.Errorf("%s: negated %s converts to %s", engine, field, s)
			}
		}
	}

	// One header searched in the whole header block, or as full text.
	r = ruleFrom(t, "sel:\n  http.title|contains: Console\nfilter:\n  http.headers.x-powered-by|contains: Express\ncondition: sel and not filter\n")
	check(t, r, map[string]want{
		"fofa":    {`title="Console"`, Superset},
		"zoomeye": {`title="Console"`, Superset},
		"shodan":  {`http.title:"Console"`, Superset},
	})
}
