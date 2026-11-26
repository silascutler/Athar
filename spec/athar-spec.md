# Athar Rule Specification

Draft. The spec has no version number of its own: it is versioned with the rules and the CLI by the repository's [release tags](https://github.com/Athar-HQ/Athar/releases).

This document defines the Athar rule format: how a rule describes a network service, what a match means, and how a rule converts to search-engine queries. Background is in the [README](../README.md), the comparison with existing formats in [prior-art.md](../docs/prior-art.md), and open questions in [decisions.md](../docs/decisions.md).

## Contents

1. [Overview](#1-overview)
2. [Rule structure](#2-rule-structure)
3. [Target](#3-target)
4. [Probes](#4-probes)
5. [Field taxonomy](#5-field-taxonomy)
6. [Detection](#6-detection)
7. [Identification](#7-identification)
8. [Families and variants](#8-families-and-variants)
9. [Tests and provenance](#9-tests-and-provenance)
10. [Conversion](#10-conversion)
11. [Out of scope for now](#11-out-of-scope-for-now)
- [Appendix A: Engine field mapping](#appendix-a-engine-field-mapping)

## 1. Overview

An Athar rule is a single YAML document that describes what one network service looks like on the wire. It reuses Sigma's metadata and its selection/condition grammar, so the `detection` block of an Athar rule is valid Sigma.

Three ideas define the format:

- **One rule matches one service**, meaning one IP address and one port. All selections of a rule must hold on that same service.
- **The scanner defines meaning.** A rule's semantics are defined against the raw response of the service. Queries generated from a rule are approximations, and each one declares how close it is.
- **Passive first.** A rule that only uses the baseline probe can be converted to search-engine queries. Extra probes are opt-in and make the parts that use them active-only.

## 2. Rule structure

Fields marked *Sigma* behave exactly as in the [Sigma specification](https://github.com/SigmaHQ/sigma-specification). The others are new.

| Field | Required | Meaning |
| --- | --- | --- |
| `title` | yes | *Sigma.* Short name of what is fingerprinted. |
| `id` | yes | *Sigma.* UUIDv4. Never changes once published. |
| `related` | no | *Sigma*, plus one new type: `variant-of` links a variant rule to its family rule (section 8). |
| `status` | yes | *Sigma.* `experimental`, `test`, `stable`, `deprecated`, `unsupported`. |
| `description` | no | *Sigma.* What it is and why the fingerprint works. |
| `references`, `author`, `date`, `modified` | no | *Sigma.* |
| `tags` | no | *Sigma* namespaces, e.g. `attack.t1588.002`, plus `category.*` (section 7) and plain tags such as `aof`. |
| `target` | yes | Protocol stack and hints (section 3). |
| `probes` | no | Extra requests beyond the baseline (section 4). Omitted means baseline only, which keeps the rule fully convertible. |
| `detection` | yes | *Sigma* selections and `condition`, over the field taxonomy (section 6). One new reserved key: `probe`. |
| `identifies` | yes | What a match is: `product`, `vendor`, `family`, `category`, `cpe`. The same for every match (section 7). |
| `extract` | no | Values read from the response after a match, such as a brand or version. Never changes whether the rule matches (section 7). |
| `confidence` | yes | How likely a match is really this service and not a lookalike: `low`, `medium`, `high`, `certain`. |
| `falsepositives` | no | *Sigma.* |
| `tests` | no | Example responses with the result the rule must give for each. `athar verify` checks them (section 9). |
| `native` | no | The original engine queries, kept as provenance. Never the source of truth (section 9). |

## 3. Target

`target` says which protocol stack the rule is about.

| Key | Required | Values |
| --- | --- | --- |
| `protocol` | yes | Application protocol: `http`, `ssh`, `ftp`, `smtp`, … Use `tcp` for rules that only look at a raw banner. |
| `transport` | no | `tcp` (default) or `udp`. |
| `tls` | no | `auto` (default): try TLS, fall back to plaintext. `required`: only match over TLS. `none`: only match plaintext. |
| `ports` | no | Typical ports, each from 1 to 65535. A hint for scanners and backends, never a match condition: when the operator gives no port list, a scanner adds these ports to the ones it checks. To require a port, use `service.port` in a selection. |

## 4. Probes

Every rule implicitly uses the **baseline probe**, `default`, which approximates what search engines index. Extra probes are opt-in. A selection that uses one is active-only.

The `default` probe per protocol:

- **TCP:** connect and read the first bytes (the banner) for up to N ms.
- **TLS** (when `tls` is `auto` and the handshake succeeds, or `required`): record the certificate chain, negotiated parameters, JARM and JA3S.
- **HTTP:** `GET /` with `Host` set to the IP, no redirect following.
- **Favicon:** the first `<link>` of the page whose `rel` contains the word `icon`, which covers `rel="icon"` and `rel="shortcut icon"` but not `apple-touch-icon`. Further icon links are ignored. An inline `data:` icon is used as it is. If the page links no icon, the link has no path of its own (`href="#"`), or the icon is on another host, the scanner requests `/favicon.ico` from the service instead; it never contacts another host. Only a `200` response counts as an icon. Engines differ on which icon they hash when a page links several, so a rule for such a page lists the hash of every icon it links.

Whether this matches how each engine actually crawls (redirects, SNI, favicon location) still has to be measured; see [decisions.md](../docs/decisions.md#open).

**Redirects.** The baseline probe records the first response and follows nothing: not a `3xx` status, not a `<meta http-equiv="refresh">`, not a script. A service whose `/` only sends the browser elsewhere shows the redirect, not the page behind it. A rule can match what that first response holds: the target of a `3xx` in `http.headers.location`, or a refresh target in `http.body`. To match the page behind the redirect, a rule declares a custom probe for its path, which makes that selection active-only. A later version of the baseline probe will follow redirects on the same service; see [decisions.md](../docs/decisions.md#baseline-follows-redirects-on-the-same-service).

Custom probes are declared once under `probes` and referenced by id. Selections bind to a probe with the reserved `probe` key. Selections without it use `default`. Illustrative example, not a real product:

```yaml
probes:
  version_api:
    protocol: http
    request:
      method: GET          # safe methods only: GET, HEAD, OPTIONS
      path: /api/version
      headers:
        Accept: application/json
  hello:
    protocol: tcp
    send: '\x00\x00\x00\x01PING'   # escaped bytes, as in nmap-service-probes
    read: { max_bytes: 512, timeout_ms: 3000 }

detection:
  selection_api:
    probe: version_api
    http.status_code: 200
    http.body|contains: '"product":"ExamplePanel"'
  condition: selection_api
```

A probe's `protocol` is `http` or `tcp`. An `http` probe takes `request` with `method`, `path` and `headers`; it has no body. A `tcp` probe takes `send` and `read`. `read` limits the answer: `max_bytes` from 1 to 1048576 (1 MiB), `timeout_ms` from 1 to 30000 (30 s). A scanner may keep fewer bytes.

Probes must be safe by construction: idempotent, unauthenticated, and without payloads that change state or try to exploit anything. Scanners must refuse non-safe HTTP methods unless an operator explicitly enables them. A shared probe library, like Nmap's, lets many rules reuse the same request, so a scanner sends it once per target.

## 5. Field taxonomy

The taxonomy is what makes a rule portable. Fields describe one service (IP and port), and a scanner fills them from the response to the bound probe.

| Field | Type | Meaning |
| --- | --- | --- |
| `service.port` | int | Port of the service. |
| `service.transport` | enum | `tcp` or `udp`. |
| `service.protocol` | string | Detected application protocol: `http`, `ssh`, `ftp`, … |
| `service.banner` | bytes | First bytes received (TCP probes), raw. |
| `http.status_code` | int | Response status. |
| `http.title` | string | HTML `<title>`, entity-decoded, whitespace-collapsed. |
| `http.body` | string | Decoded body, first 1 MiB (limit to be agreed). |
| `http.body.mmh3` | int | MurmurHash3 of the complete body after transfer and content decoding, not of the truncated `http.body`; Shodan `http.html_hash` style. Absent where `http.body.sha256` is. |
| `http.body.sha256` | hex | SHA-256 of the complete body after transfer and content decoding, not of the truncated `http.body`. Absent if the body was cut short before its end or is longer than the scanner hashes (16 MiB in `athar scan`). |
| `http.headers.<name>` | string | One header by lowercase name, e.g. `http.headers.server`. Repeated headers form a list. Every header in the block as received has its field, `Transfer-Encoding` and `Connection` included. |
| `http.headers_raw` | string | The full header block as received, status line included, for engines that only search raw headers. |
| `http.favicon.mmh3` | int | Shodan/FOFA algorithm: mmh3 over base64 with a newline every 76 characters. Like the body hashes, the favicon hashes are of the complete icon and absent otherwise. |
| `http.favicon.md5` | hex | MD5 of the icon bytes (OWASP favicon database, several engines). |
| `http.favicon.sha256` | hex | SHA-256 of the icon bytes (Censys Platform). |
| `tls.version`, `tls.cipher`, `tls.alpn` | string | Negotiated parameters. |
| `tls.jarm` | string | JARM fingerprint. |
| `tls.ja3s` | string | JA3S of the ServerHello. |
| `tls.ja4s` | string | Optional; FoxIO License 1.1. |
| `tls.cert.subject.cn`, `.o`, `.dn` | string | Leaf certificate subject. |
| `tls.cert.issuer.cn`, `.o`, `.dn` | string | Leaf certificate issuer. |
| `tls.cert.serial` | string | Serial number, hex. |
| `tls.cert.sha256`, `tls.cert.sha1` | hex | Certificate fingerprints. |
| `tls.cert.san` | list | Subject Alternative Names. |
| `tls.cert.self_signed` | bool | Subject equals issuer and the signature verifies with its own key. |
| `tls.cert.ja4x` | string | Optional; FoxIO License 1.1. |
| `ssh.banner` | string | Server identification string, e.g. `SSH-2.0-OpenSSH_9.6`. |
| `ssh.hostkey.sha256` | hex | Host key fingerprint. |
| `ssh.kex_algorithms` | list | Offered key-exchange algorithms. |

`http.body` and `http.title` are UTF-8 text. A scanner decodes the body from the charset the response declares: in the `Content-Type` header, else in a `<meta>` tag within the first 1024 bytes (the HTML standard's prescan), else with a UTF-16 byte order mark. Without a declaration, or with a label the scanner doesn't know, the bytes are kept as received; the charset is never guessed from the content. The body hashes are over the raw body, before this decoding.

Three rules keep the taxonomy portable:

- **Hash fields name their algorithm** (`.mmh3`, `.md5`, `.sha256`). A scanner computes all of them; a backend uses the one its engine supports.
- **Engine-proprietary values** (FOFA `fid` and `app`, Shodan `http.component`, Censys labels, Modat `fingerprints.*` and `tag`, urlscan verdicts, brands and `content.technologies`) are not taxonomy fields. They go into `native` or an `x-<engine>.` namespace that other backends and the scanner ignore.
- **Engine-specific header hashes** (FOFA `header_hash`, ZoomEye `http.header_hash`) stay out until their algorithms are documented.

## 6. Detection

Detection is Sigma's grammar, unchanged except for the `probe` key. A map is AND, a list of maps is OR, a list of values is OR. The `condition` combines named selections with `and`, `or`, `not`, parentheses, `1 of selection_*` and `all of them`.

**Same service.** All selections must hold on the same service (one IP and port). A scanner does this implicitly. Backends must enforce it where an engine indexes whole hosts.

**Matching.** String matching is case-insensitive by default, as in Sigma. A bare value is an exact match. This differs from FOFA, where `title="x"` is a substring match; backends handle such differences, authors don't. As in Sigma, `*` and `?` in a value are wildcards (`\*`, `\?` and `\\` are literals), and a `re` expression is used as written, so it is case-sensitive unless it starts with `(?i)`. A value for a string or `hex` field is the text the rule gives, also where YAML reads an unquoted value as a number, a boolean or a date: `tls.cert.serial: 0100` is `0100`, not 64. The same holds for the response values in `tests`. Values of `int` and `bool` fields, of `exists` and of the numeric comparisons are read as YAML reads them.

**List fields.** Some fields hold several values: `tls.cert.san`, `ssh.kex_algorithms`, and any header the response sends more than once, such as `http.headers.set-cookie`. A condition on such a field holds when at least one element matches. Each element is compared on its own, so `tls.cert.san|endswith: '.nip.io'` or an anchored `re` tests one name at a time, never the joined list. With `all`, every listed value must match some element, not necessarily the same one. Under `not`, one matching element is enough to exclude the service.

| Modifier | Source | Meaning |
| --- | --- | --- |
| `contains`, `startswith`, `endswith` | Sigma | Substring position. |
| `all` | Sigma | Every listed value must match (default is any). |
| `re` | Sigma | Regular expression in RE2 syntax, so every implementation agrees. |
| `cased` | Sigma | Case-sensitive match. |
| `exists` | Sigma | Field present or absent. |
| `gt`, `gte`, `lt`, `lte` | Sigma | Numeric comparison, e.g. status codes or certificate validity. |
| `cidr` | Sigma | For address fields, rarely needed. |
| `hex` | new | Value is given as hex, for binary banners. |

**Keywords.** Sigma's `keywords` selection (a bare list of strings) is kept for full-text search. It matches across `service.banner`, `http.headers_raw` and `http.body`, and maps to every engine's free-text search.

A filter excludes what a selection would otherwise include. This detection finds consoles of the ARTEX family that no longer serve the original ARTEX favicon, which is how rebrands surface:

```yaml
detection:
  selection_title:
    http.title|contains:
      - '自主渗透测试控制台'
      - '자율 침투 테스트 콘솔'
      - 'Autonomous Penetration Testing Console'
  filter_artex_icon:
    http.favicon.mmh3: -576220750
  condition: selection_title and not filter_artex_icon
```

## 7. Identification

`detection` decides **whether** a service matches. `identifies` and `extract` describe **what** it is once it has matched:

- **`identifies`** holds the facts that are the same for every match: `product`, `vendor`, `family`, `category`, `cpe`. The author writes them into the rule. A family rule may leave `product` empty and fill it through extraction.
- **`extract`** reads the facts that differ from one match to the next, such as a brand name or a version, out of the response.

They run in that order. The scanner evaluates `detection` first and runs `extract` on the same response only if the rule matched. `extract` never changes the outcome: if its pattern finds nothing, the service still matches and the value is left out of the record. A field that `extract` reads does not have to appear in `detection`.

The family rule shows the split. `detection` matches every brand by the title suffix they share, in Chinese, Korean or English; `extract` then reads which brand this deployment shows from the part of the title before the suffix.

```yaml
detection:
  selection_title:
    http.title|contains:
      - '自主渗透测试控制台'
      - '자율 침투 테스트 콘솔'
      - 'Autonomous Penetration Testing Console'
  condition: selection_title
identifies:
  family: artex
  category: offensive-tool
extract:
  brand:
    field: http.title
    regex: '^(?P<brand>.+?)\s*[—–\-:·]\s*(?:自主渗透测试控制台|자율 침투 테스트 콘솔|(?i:Autonomous Penetration Testing Console))'
```

For the title `ARTEX — 自主渗透测试控制台` the record gets `brand: ARTEX`, and for `NKW: 자율 침투 테스트 콘솔` it gets `brand: NKW`. A console whose title is only the suffix, `自主渗透测试控制台`, still matches; its record has no brand.

Each `extract` entry is named after the value it produces and gives the `field` to read plus either an RE2 `regex` or a `jsonpath` for JSON bodies. The value is the regex group named like the entry (`(?P<brand>…)` for `brand`), else the first group, else the whole match. This is the same idea as Recog's `param` elements.

**`category`** comes from a controlled list: `c2`, `offensive-tool`, `phishing-kit`, `malware-panel`, `remote-access`, `ai-infrastructure`, `network-appliance`, `ics`, `iot`, `cms`, `web-server`, `database`. The tag `category.<category>` repeats it.

What a scanner emits for one matched service:

```json
{
  "target": "176.31.234.8:80",
  "tls": false,
  "rule": "0ce69e91-baee-4475-81ee-4b8eca1a6c3b",
  "title": "Agentic Offensive Framework - ARTEX family",
  "author": "Gameel Ali (@MalGamy12)",
  "family": "artex",
  "category": "offensive-tool",
  "extracted": { "brand": "NKW" },
  "confidence": "high",
  "matched": ["selection_title"],
  "probes": ["default"],
  "observed": "2026-11-24T19:46:00Z"
}
```

`author` comes from the rule. Rules in the Athar repository are licensed under the [Detection Rule License 1.1](../LICENSE.Detection.Rules.md), which asks every message based on a rule's match to name the rule's author, so a scanner should always include it.

When several rules match one service, every matching rule yields one record, with one exception: the record of a family rule is left out when one of its variants (section 8) matched the same service. Each such variant's record then also carries the values the family extracted; a value the variant extracts itself wins. Records are ordered by `confidence`, highest first. This mirrors Nmap's hard match over soft match. A scanner that runs one template per rule, such as Nuclei, cannot leave a record out and reports both the family and the variant.

## 8. Families and variants

Rebrands of one codebase (for example ARTEX, NKW, ARGOS and AntiFox) are one **family rule** plus **variant rules**:

- The family rule matches every brand and usually extracts the brand name.
- A variant rule links to its family with `related` type `variant-of` and adds what identifies the variant (title prefix, favicon, certificate).
- A variant repeats the family's selections, so each file converts on its own. `athar verify` checks that a `variant-of` rule implies its family: both have the same `identifies.family`, and every selection the family's condition requires is repeated by a selection the variant's condition requires (the condition itself or a term of its top-level `and`), with the same probe, fields, modifiers and values; of a list of alternative values the variant may keep fewer. A variant that fails this is an error. If the check can't decide, because the family's condition has an `or` or a `not` or the variant's requires no selection, it is a warning, and a scanner then reports the family as well as the variant.

```yaml
related:
  - id: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
    type: variant-of
```

## 9. Tests and provenance

These two sections are about the rule itself, not about the service it describes. `tests` is checked by a tool; `native` is a note.

**`tests`** are example responses together with the result the rule must give for each. A test contacts nothing: it writes a response down, as taxonomy fields or as the HTTP response a server sent (`raw`), and `athar verify` runs the rule against it exactly as the scanner would run it against a live service. CI runs `athar verify` on every pull request, and a rule with a failing test does not merge.

A rule needs both kinds:

- A **`match`** test is a response the rule must recognise. Without one, nothing shows that the rule matches anything.
- A **`no_match`** test is a near miss the rule must reject, such as a similar title on an unrelated page. It catches rules that are too loose.

When someone later edits a selection, the tests show at once whether the rule stopped matching the real service or started matching the near miss.

A `match` test can also check what `extract` reads. This test passes only if the rule matches the title and `extract` finds the brand `NKW` in it:

```yaml
tests:
  - name: English title
    response:
      http.title: 'NKW — Autonomous Penetration Testing Console'
    expect: match
    extracted:
      brand: NKW
```

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Short description of the case. |
| `raw` | no | One HTTP response to the baseline probe as received: status line, header lines, body. `athar verify` derives the fields from it; see below. |
| `response` | yes, unless `raw` or `probes` is given | Taxonomy fields and their values for the baseline probe. Fields not listed are absent. Next to `raw`, they are added to the derived fields and win over them. |
| `probes` | no | Responses to custom probes, by probe id, with the same taxonomy fields, or with `raw` for an HTTP probe. A custom probe the test does not list got no response, so selections bound to it do not hold. |
| `expect` | yes | `match` or `no_match`. |
| `extracted` | no | On a `match` test, the values `extract` must find in this response, by name. |

A captured response goes under `raw`. `athar verify` reads it with the scanner's own code, so the test runs on the fields a live scan gives, and nobody has to work them out by hand. Here the title comes out as `ARTEX — Autonomous Penetration Testing Console`, and `response` adds the favicon, which an HTTP response does not carry:

```yaml
tests:
  - name: Landing page as received
    expect: match
    raw: |
      HTTP/1.1 200 OK
      Content-Type: text/html; charset=utf-8

      <html><head><title>ARTEX &mdash; Autonomous Penetration Testing Console</title></head></html>
    response:
      http.favicon.mmh3: -576220750
```

`raw` gives the fields the scanner reads from one HTTP response: `http.status_code`, `http.title`, `http.body`, the body hashes, `http.headers.<name>`, `http.headers_raw` and `service.protocol`. It gives no favicon, TLS or banner fields; list those under `response`. A `raw` that is not an HTTP response fails the test.

- **Line ends.** The head is everything up to and including the first empty line. A head without a CR, as a YAML block scalar (`|`) gives it, is read with CRLF line ends, and its empty line may be left out when no body follows. A head that has a CR is taken as written.
- **Body.** The body is taken byte for byte and read as the scanner reads it: it ends where `Content-Length` or the chunks say, or else at the end of the text, and a gzip body is decoded. A `|` block scalar ends with one newline and `|-` with none; without `Content-Length` that newline is part of the body and changes the body hashes.
- **Exact bytes.** Write a double-quoted string with escapes, `"HTTP/1.1 200 OK\r\n\r\n…"`. Bytes that are not valid UTF-8 need `!!binary` with base64.

A rule that checks a file's hash fetches the file with a custom probe, and its tests give the file's response under `probes`:

```yaml
probes:
  css_4384baud_6ozc:
    protocol: http
    request:
      path: /_next/static/chunks/4384baud_6ozc.css
detection:
  selection_file_css_4384baud_6ozc:
    probe: css_4384baud_6ozc
    http.body.sha256: ff75f55ed6baeb22cee166fd7281a5f3b9243678b9b04ae41c8a84ae39cc02f5
  condition: 1 of selection_file_*
tests:
  - name: ARTEX console serving the stylesheet
    expect: match
    response:
      http.title: 'ARTEX — 自主渗透测试控制台'
    probes:
      css_4384baud_6ozc:
        http.status_code: 200
        http.body.sha256: ff75f55ed6baeb22cee166fd7281a5f3b9243678b9b04ae41c8a84ae39cc02f5
```

**`native`** keeps the original engine queries as provenance, keyed by engine name: `fofa`, `shodan`, `censys`, `zoomeye`, `modat`, `urlscan`, `huntio`. Converters never read it.

## 10. Conversion

A backend turns a rule into one engine's query and labels the result with its fidelity. Warnings are returned, not swallowed.

| Fidelity | Meaning | Example |
| --- | --- | --- |
| `exact` | Same result set as the scanner on the engine's data | Family rule on FOFA |
| `approximate` | Same intent, looser operator (tokenized, substring for prefix), or an engine field that is not verified yet (Appendix A, †) | `startswith` on FOFA |
| `superset` | Unsupported parts dropped, so the query can only over-match | A custom-probe selection removed |
| `unsupported` | Nothing meaningful left | A rule that is only a regex, on Shodan |

**Superset rule.** Replace each unconvertible selection with TRUE where it sits under an even number of `not`s, and with FALSE under an odd number, then simplify. The result can only return more services, never fewer, and the scanner confirms the rest. If the query collapses to TRUE, the backend refuses.

**`target.tls`.** Engine queries leave out `tls: required` and `tls: none`, so an `exact` query becomes a `superset` with a note, unless a certificate or handshake condition already limits a `required` rule to TLS; scanner templates keep the constraint.

**Operators do not line up across engines:**

- `contains` is native on FOFA and ZoomEye (`=`) and on Modat (`~`) for fields such as `http.title`. It is approximate on Shodan and Censys (`:`), which tokenize text, on Modat's `http.body`, `http.headers` and `banner`, which only match whole words, and on Hunt.io (`LIKE '%…%'`), which is case-sensitive. On Censys a `cased` or wildcard `contains`, and one on a field its subdomain analyzer splits, goes through `=~` instead and stays exact.
- Exact match is `==` on FOFA, ZoomEye and Hunt.io and `=` on Censys and Modat; Shodan has none. Modat's `==` and `~~` are the case-sensitive forms, for `cased`; Censys's `=` is case-sensitive too, so it carries a `cased` match and an exact match that ignores case becomes an anchored `(?i)` regex. Hunt.io's `==` and `LIKE` are always case-sensitive, so only `cased` matches convert exactly there. Where an engine's search ignores case, a `cased` match is approximate.
- `startswith`, `endswith` and `re` only convert exactly on Censys and Modat (`=~` with anchors). On Modat this works on `http.title`, certificate names and single headers, not on the body or banner, and only for patterns its smaller regex dialect can express. On Censys they work on every text field, including single headers, with the limits in the Censys bullet below. Hunt.io's `LIKE` is anchored, so `startswith` and `endswith` convert there (`'value%'`, `'%value'`), but `re` does not. Elsewhere they degrade to `contains`.
- Under `not` a looser operator excludes too much: `not startswith "ARTEX"` as FOFA's `title!="ARTEX"` would also hide titles that only contain ARTEX, which the rule matches. A negated exact, prefix or suffix match that an engine can only search as a substring or as words, a negated `cased` match that it can only search without regard to case, and a negated field that it maps to a wider one (a single header searched in the whole header block, a body or favicon SHA-256 as urlscan's `hash`) count as unconvertible and are dropped by the superset rule.
- Quoting: a quote or backslash in a value is escaped as the engine documents it, in the quoted string and, for `=~`, in the regex inside it, so it can never end the string. A character an engine documents no spelling for is unconvertible: a backslash on Modat and Hunt.io, and a control character such as a line break in any query.
- Single headers: Modat searches one header by name and value, `http.headers: (key = "Server" and value ~ "nginx")`, and Censys the same way, `endpoints.http.headers: (key = "Server" and value =~ "(?i)^nginx$")`; both match `http.headers.<name>` exactly. Neither can test a header for presence alone. FOFA and ZoomEye search the raw header block and Shodan only full text.
- Same service: Censys needs the nested form `host.services: ( … )`. Modat records are per service at service level; at host level the query goes into `same_service( … )`. Hunt.io's `ip.current` has one row per IP with its services nested under it, so the condition goes into `same_port( … )`. FOFA, ZoomEye and Shodan records are already per service.
- Censys Platform is searched with CenQL. `:` ignores case but tokenizes, so it carries a plain `contains` and nothing else; every other operator goes through `=~`, whose regex is case-sensitive and unanchored. The backend therefore adds `(?i)` unless the match is `cased`, and `^` or `$` for an exact, prefix or suffix match. Censys accepts `^` only as the first character of a pattern and `$` only as the last, so a rule regex that anchors anywhere else does not convert; its dialect is also smaller than RE2, which keeps `re` approximate. `=` is an exact, case-sensitive match. `*` and `?` stopped being wildcards outside regex, so Sigma wildcards convert as `.*` and `.`. `field: *` tests for presence, and `<`, `<=`, `>`, `>=` compare numbers, dates and addresses with the value quoted. The certificate common names and `cert.names` run through a subdomain analyzer that matches whole domain labels, so a substring on them uses a regex too. Regex searches need a Starter tier account or above, and `jarm`, `ja3s` and `ja4s` the Adversary Investigation module.
- urlscan.io records pages, not services: what a browser showed for a URL someone submitted, after redirects. It has no field for the body, banner, port, certificate subject or any header but `Server`, so most rules convert to a superset. It indexes every value in lowercase and uses the Elasticsearch query string (`AND`, `OR`, `NOT`). `http.title` converts exactly with regexes on `page.title.keyword`, which urlscan anchors at both ends: `contains` becomes `/.*value.*/`, `startswith` becomes `/value.*/`. Regex searches need a signed-in account. `re` does not convert, because urlscan's regex dialect is not RE2. urlscan is the one engine that indexes more than the baseline probe: it stores the SHA-256 of every file a page loads, so the `http.body.sha256` of a custom probe that fetches a file converts to `hash:` (approximate: it finds the pages that loaded the file). No other engine searches custom probes. Lucene reads `a OR NOT b` as `a AND NOT b`, so a negation inside OR gets its own group: `a OR (NOT b)`.
- Hunt.io is searched with HuntSQL, a read-only SQL dialect. A query is a complete statement on the `ip.current` table, `SELECT ip, service.port FROM ip.current WHERE same_port( … )`. `LIKE` follows SQL: anchored at both ends, `%` and `_` as wildcards, so Sigma's `*` and `?` become `%` and `_`, and a literal `%` or `_` in a value makes the match approximate. Negations become `NOT ( … )`. `RLIKE` is anchored at both ends too, and its regex dialect is not documented, so `re` does not convert. Values are written in single quotes, or in double quotes when they hold a single quote; HuntSQL documents no escapes, so a value with a backslash or with both kinds of quotes is unconvertible. Hunt.io has no full-text field and no JA3S. Without a timestamp condition it searches the rows of the last 30 days.

**Body truncation.** Engines index only part of large bodies; a Censys host service endpoint [indexes the first 64 KB of a body and the first 2 KB of the header block](https://docs.censys.com/docs/platform-host-dataset), and its body hash covers the same 64 KB. (Censys's [6 KB limit](https://docs.censys.com/changelog/august-24-2026) is for name-based web properties, which a `host.services` query does not search.) A `body` match deep in a page, or a header past the first 2 KB, can be missed by the engine but found by the scanner.

Example conversions of the ARTEX rules in [rules/offensive-tool/](../rules/offensive-tool/), as `athar convert` prints them. The family rule is three alternative titles:

```text
Family, FOFA (exact):
  title="自主渗透测试控制台" || title="자율 침투 테스트 콘솔"
  || title="Autonomous Penetration Testing Console"

Family, Shodan (approximate: text is tokenised). Shodan has no OR between
conditions, but it reads a comma-separated value list as "any of these":
  http.title:"自主渗透测试控制台","자율 침투 테스트 콘솔","Autonomous Penetration Testing Console"

Family, Censys Platform (approximate: ':' is tokenised):
  host.services: (endpoints.http.html_title: "自主渗透测试控制台"
                  or endpoints.http.html_title: "자율 침투 테스트 콘솔"
                  or endpoints.http.html_title: "Autonomous Penetration Testing Console")

Family, Modat at service level (exact):
  http.title~"自主渗透测试控制台" or http.title~"자율 침투 테스트 콘솔"
  or http.title~"Autonomous Penetration Testing Console"

Family, urlscan.io (exact: values are lowercase, regexes are anchored):
  page.title.keyword:/.*自主渗透测试控制台.*/ OR page.title.keyword:/.*자율 침투 테스트 콘솔.*/
  OR page.title.keyword:/.*autonomous penetration testing console.*/

Family, Hunt.io (approximate: LIKE is case-sensitive):
  SELECT ip, service.port FROM ip.current
  WHERE same_port(html.head.title LIKE '%自主渗透测试控制台%'
                  OR html.head.title LIKE '%자율 침투 테스트 콘솔%'
                  OR html.head.title LIKE '%Autonomous Penetration Testing Console%')
```

The ARTEX rule adds `title starts with ARTEX or the ARTEX favicon`:

```text
ARTEX, FOFA (approximate: startswith becomes contains):
  (title="自主渗透测试控制台" || title="자율 침투 테스트 콘솔"
   || title="Autonomous Penetration Testing Console")
  && (title="ARTEX" || icon_hash="-576220750")

ARTEX, Shodan (superset): the alternative of a title prefix and a favicon
spans two filters, so it is dropped and only the family titles remain.
  http.title:"自主渗透测试控制台","자율 침투 테스트 콘솔","Autonomous Penetration Testing Console"

ARTEX, Censys Platform (superset): Censys has no favicon mmh3, so the
alternative is dropped and the family query remains.

ARTEX, Modat (exact: =~ is a case-insensitive regex):
  (http.title~"自主渗透测试控制台" or http.title~"자율 침투 테스트 콘솔"
   or http.title~"Autonomous Penetration Testing Console")
  and (http.title=~"^ARTEX" or http.files.mmh3=-576220750)

ARTEX, urlscan.io (superset): urlscan has no favicon mmh3, so the
alternative is dropped and the family query remains.
```

The Basic auth rule matches one header, which Censys and Modat can search by name:

```text
Basic auth, Modat at service level (exact):
  http.headers: (key = "Www-Authenticate"
                 and value = "Basic realm=\"ARTEX\", charset=\"UTF-8\"")

Basic auth, Censys Platform (exact: the regex is anchored and (?i) restores
the rule's case-insensitive match):
  host.services: (endpoints.http.headers:
                    (key = "Www-Authenticate"
                     and value =~ "(?i)^Basic realm=\\\"ARTEX\\\", charset=\\\"UTF-8\\\"$"))

Basic auth, FOFA (approximate: the value is searched in the whole header block):
  header="Basic realm=\"ARTEX\", charset=\"UTF-8\""

Basic auth, urlscan.io (unsupported): urlscan indexes no header but Server.
```

At Modat host level, a query goes into `same_service( … )`.

**Scanner templates.** A backend can also write a template for another scanner; `athar convert` writes Nuclei templates and data for an Nmap script. The fidelity labels then compare the template with Athar's scanner on the same service: `exact` means the template matches the same responses. The superset rule applies unchanged. A template keeps the rule's `author` and names its licence.

## 11. Out of scope for now

- **Multi-service fingerprints**, where only a combination of ports on one host identifies a service. Deferred; see [decisions.md](../docs/decisions.md#multi-service-fingerprints).
- **Engine-specific header and body hashes** whose algorithms are undocumented (section 5).
- **Rule inheritance** (`extends`). Variants repeat their family's selections for now.

## Appendix A: Engine field mapping

Informative. This is the first draft of the mapping backends use. Cells marked † come from secondary sources or are inferred and are not checked against the engine docs yet: a query that uses such a field is `approximate` at best and carries a note that says so. A dash means the engine has no such field. "Not converted" means the engine has the field but the backend leaves it out. Modat cells name the field only: `~` is contains, `=` exact, `=~` regex. urlscan cells name the field too; urlscan indexes values in lowercase and allows regexes only on `.keyword` fields. Hunt.io cells name columns of its `ip.current` table: text columns are searched with `LIKE`, the others with `==`.

| Field | FOFA | Shodan | Censys Platform | ZoomEye | Modat Magnify | urlscan.io | Hunt.io |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `http.title` | `title=` | `http.title:` | `host.services.endpoints.http.html_title` | `title=` | `http.title` | `page.title.keyword` (regex) | `html.head.title` |
| `http.body` | `body=` | `http.html:` | `host.services.endpoints.http.body` | `http.body=` | `http.body` (whole words) | — | `html.body.content` |
| `http.headers.server` | `server=`† | full text `"Server: …"` | `…endpoints.http.headers: (key = "Server" and value …)` | `http.header.server=` | `http.headers: (key = "Server" and value …)` | `page.server` (words) | `http.headers.server` |
| other headers | `header=` on raw block | full text | `…endpoints.http.headers: (key = "…" and value …)` | `http.header=` on raw block | `http.headers: (key = "…" and value …)` | — | `http.headers.bytes.content` on raw block; `http.headers.x_powered_by`, `http.headers.etag` by name |
| `http.status_code` | `status_code=`† | `http.status:` | `…http.status_code` | `http.header.status_code=` | `http.status_code` | `page.status` | `http.headers.status.code` |
| `http.favicon.mmh3` | `icon_hash=` | `http.favicon.hash:` | — | `iconhash=` | `http.files.mmh3` | — | `favicon.hash.mmh3` |
| `http.favicon.md5` | — | — | `…http.favicons.hash_md5` | `iconhash=` | — | — | `favicon.hash.md5` |
| `http.favicon.sha256` | — | — | `…http.favicons.hash_sha256` | — | `http.files.sha256` | `hash` (any response) | `favicon.hash.sha256` |
| `http.body.mmh3` | `body_hash=`† (algorithm undocumented, not converted) | `http.html_hash:`† | — | — | `http.body_mmh3`† | — | `html.body.hash.murmur3`† (variant undocumented, not converted) |
| `http.body.sha256` | — | — | `…http.body_hash_sha256` | — | `http.body_sha256` | `hash` (any response) | `html.body.hash.sha256` |
| `tls.cert.subject.cn` | `cert.subject.cn=` | `ssl.cert.subject.cn:` | `host.services.cert.parsed.subject.common_name` (subdomain analyzer) | `ssl.cert.subject.cn=` | `tls.subject.common_name` | — | `tls.cert.subject.common_name` |
| `tls.cert.issuer.cn` | `cert.issuer.cn=`† | `ssl.cert.issuer.cn:` | `host.services.cert.parsed.issuer.common_name` (subdomain analyzer) | `ssl.cert.issuer.cn=` | `tls.issuer.common_name` | `page.tlsIssuer` | `tls.cert.issuer.common_name` |
| `tls.cert.subject.dn` | — | — | `host.services.cert.parsed.subject_dn` | — | — | — | — |
| `tls.cert.issuer.dn` | — | — | `host.services.cert.parsed.issuer_dn` | — | — | — | — |
| `tls.cert.san` | — | — | `host.services.cert.names` (subdomain analyzer) | — | — | — | — |
| `tls.cert.sha256` | —† | `ssl.cert.fingerprint:`† (hash algorithm unchecked, not converted) | `host.services.cert.fingerprint_sha256` | —† | `tls.fingerprint_sha256` | — | `tls.cert.hash.sha256` |
| `tls.cert.sha1` | — | — | `host.services.cert.fingerprint_sha1` | — | — | — | — |
| `tls.jarm` | `jarm=` | `ssl.jarm:` | `host.services.jarm.fingerprint` | `ssl.jarm=` | `tls.jarm` | — | `jarm.fingerprint` |
| `tls.ja3s` | —† | `ssl.ja3s:` | `host.services.tls.ja3s` | `ssl.ja3s=` | `tls.ja3s` | — | — |
| `tls.ja4s` | — | — | `host.services.tls.ja4s` | — | — | — | — |
| `service.banner` | `banner=` | full text | `host.services.banner` | `banner=` | `banner` (whole words) | — | `protocol.data`† (probe undocumented, not converted) |
| `service.port` | `port=` | `port:` | `host.services.port` | `port=` | `port` | — | `service.port` |
| `keywords` | bare `"…"` | bare terms | full-text query (not converted: it can't be nested in `host.services`) | bare `"…"` | bare terms | — | — |

Engine references:

- [Censys Query Language](https://docs.censys.com/docs/censys-query-language): operators, tokenization, aliases, nested fields
- [Regex in CenQL](https://docs.censys.com/docs/platform-regex-cenql): `=~` is case-sensitive and unanchored, `(?i)` and the dialect's operators
- [Censys Platform host dataset (nested fields)](https://docs.censys.com/docs/platform-host-dataset): index limits (64 KB body, 2 KB headers, 384 KB favicon)
- [Censys Platform TLS data](https://docs.censys.com/docs/platform-tls-data)
- [Censys Platform JARM fields](https://docs.censys.com/docs/platform-jarm-fingerprints)
- [Censys Platform syntax differences](https://docs.censys.com/docs/censys-platform-syntax-differences): `*` and `?` are no longer wildcards outside regex
- [Shodan: property hashes](https://help.shodan.io/mastery/property-hashes)
- [ZoomEye search syntax guide](https://dev.to/stark_zhuang_df5076f35c68/a-complete-guide-to-the-latest-zoomeye-search-syntax-4loo)
- [Modat Magnify: operators, quoting, negation](https://magnify.modat.io/docs/tips)
- [Modat Magnify: web content fields and single-header search](https://magnify.modat.io/docs/web-content-search)
- [Modat Magnify: whole-word and substring fields](https://magnify.modat.io/docs/index-tokenisation-approach)
- [Modat Magnify: `same_service`](https://magnify.modat.io/docs/host-search)
- [Modat Magnify: certificate and TLS fingerprint fields](https://magnify.modat.io/docs/certificate-search)
- [Modat Magnify API (OpenAPI)](https://api.magnify.modat.io/docs)
- [urlscan.io Search API reference: fields, types and query syntax](https://urlscan.io/docs/search/)
- [Hunt.io HuntSQL](https://hunt.io/support/huntsql); the SQL docs and the `ip.current` schema are in the portal, behind a sign-in
- [FOFA syntax reference (mirror, Chinese)](https://gitcode.csdn.net/6aa0d90a1a35784c842067d5.html)
