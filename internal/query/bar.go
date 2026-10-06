package query

import (
	"errors"
	"strings"
	"time"
)

// ParseWhen reads YYYY, YYYY-MM, YYYY-MM-DD or RFC 3339, in UTC. search's
// flags and explore's bar both use it.
func ParseWhen(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02", "2006-01", "2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("unrecognised time")
}

type barTerm struct {
	key    string // "" for a bare term
	value  string
	quoted bool
}

// splitBar splits the bar into terms: key:value or a bare value, values
// optionally in double quotes with \" and \\ escapes.
func splitBar(s string) ([]barTerm, error) {
	var out []barTerm
	r := []rune(s)
	for i := 0; i < len(r); {
		if r[i] == ' ' || r[i] == '\t' {
			i++
			continue
		}
		var t barTerm
		start := i
		if r[i] != '"' {
			for i < len(r) && r[i] != ' ' && r[i] != '\t' && r[i] != ':' && r[i] != '"' {
				i++
			}
			if i < len(r) && r[i] == ':' {
				t.key = strings.ToLower(string(r[start:i]))
				i++
			} else {
				i = start
			}
		}
		if i < len(r) && r[i] == '"' {
			t.quoted = true
			i++
			var b strings.Builder
			closed := false
			for i < len(r) {
				c := r[i]
				i++
				if c == '\\' && i < len(r) && (r[i] == '"' || r[i] == '\\') {
					b.WriteRune(r[i])
					i++
					continue
				}
				if c == '"' {
					closed = true
					break
				}
				b.WriteRune(c)
			}
			if !closed {
				return nil, usage("unclosed quote in %q", s)
			}
			if i < len(r) && r[i] != ' ' && r[i] != '\t' {
				return nil, usage("a quoted value must end its term: %q", string(r[start:]))
			}
			t.value = b.String()
		} else {
			vs := i
			for i < len(r) && r[i] != ' ' && r[i] != '\t' {
				i++
			}
			t.value = string(r[vs:i])
		}
		out = append(out, t)
	}
	return out, nil
}

// barKeys are the bar's key: terms (amendment A4 §2.1).
var barKeys = map[string]bool{"suffix": true, "exact": true, "ip": true, "contains": true, "regex": true, "issuer": true, "org": true,
	"issuer-org": true, "issued-by": true, "key": true, "key-alg": true, "kind": true, "status": true, "parse-status": true,
	"valid-at": true, "log": true, "since": true, "until": true, "by": true}

// IsBarKey reports whether k: begins a term of the bar.
func IsBarKey(k string) bool { return barKeys[k] }

var barModes = map[string]Mode{"suffix": ModeSuffix, "exact": ModeExact, "ip": ModeIP, "contains": ModeContains, "regex": ModeRegex}

// ParseBar parses explore's query bar (amendment A4 §2.1) into the same
// Query search builds from its flags: one search term, bare for a domain or
// suffix:, exact:, ip:, contains:, regex:, then filters.
func ParseBar(text string) (Query, error) {
	var q Query
	terms, err := splitBar(text)
	if err != nil {
		return q, err
	}
	modes := 0
	setMode := func(m Mode, v string) {
		q.Mode, q.Text = m, v
		modes++
	}
	when := func(key, v string) (*time.Time, error) {
		t, err := ParseWhen(v)
		if err != nil {
			return nil, usage("%s:%s: use YYYY, YYYY-MM, YYYY-MM-DD or RFC 3339", key, v)
		}
		return &t, nil
	}
	for _, t := range terms {
		v := t.value
		switch t.key {
		case "":
			if v == "wildcard" && !t.quoted {
				q.Wildcard = true
				continue
			}
			setMode(ModeDomain, v)
		case "suffix", "exact", "ip", "contains", "regex":
			setMode(barModes[t.key], v)
		case "issuer":
			q.Issuer = v
		case "org", "issuer-org":
			q.IssuerOrg = v
		case "issued-by":
			q.IssuedBy = v
		case "key", "key-alg":
			q.KeyAlg = v
		case "kind":
			for _, k := range strings.Split(v, ",") {
				if k = strings.TrimSpace(k); k != "" {
					q.Kinds = append(q.Kinds, k)
				}
			}
		case "status", "parse-status":
			q.ParseStatus = v
		case "valid-at":
			if q.ValidAt, err = when(t.key, v); err != nil {
				return q, err
			}
		case "log":
			q.Log = v
		case "since":
			if q.Since, err = when(t.key, v); err != nil {
				return q, err
			}
		case "until":
			if q.Until, err = when(t.key, v); err != nil {
				return q, err
			}
		case "by":
			switch v {
			case "not-before":
				q.ByNotBefore = true
			case "ct-ts":
			default:
				return q, usage("by:%s (ct-ts or not-before)", v)
			}
		default:
			return q, usage("unknown term %q", t.key+":")
		}
		if t.key != "" && v == "" && !t.quoted {
			return q, usage("%s: needs a value", t.key)
		}
	}
	if modes != 1 {
		return q, usage("give exactly one search term: a domain, or suffix:, exact:, ip:, contains: or regex:")
	}
	return q, nil
}

// barValue quotes a value when the bar needs it.
func barValue(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\":") && v != "wildcard" {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func barTime(t time.Time) string {
	t = t.UTC()
	if t.Equal(t.Truncate(24 * time.Hour)) {
		return t.Format("2006-01-02")
	}
	return t.Format(time.RFC3339Nano)
}

// Bar renders q in the bar's syntax, with short names, in a fixed order.
func (q Query) Bar() string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+":"+barValue(v))
		}
	}
	if q.Mode == ModeDomain {
		parts = append(parts, barValue(q.Text))
	} else {
		add(string(q.Mode), q.Text)
	}
	add("issuer", q.Issuer)
	add("org", q.IssuerOrg)
	add("issued-by", q.IssuedBy)
	add("key", q.KeyAlg)
	add("kind", strings.Join(q.Kinds, ","))
	add("status", q.ParseStatus)
	if q.ValidAt != nil {
		add("valid-at", barTime(*q.ValidAt))
	}
	if q.Wildcard {
		parts = append(parts, "wildcard")
	}
	add("log", q.Log)
	if q.Since != nil {
		add("since", barTime(*q.Since))
	}
	if q.Until != nil {
		add("until", barTime(*q.Until))
	}
	if q.ByNotBefore {
		parts = append(parts, "by:not-before")
	}
	return strings.Join(parts, " ")
}
