// Package pdp is a Go port of the policy decision point in boundary.py: it decides ALLOW,
// REDACT-THEN-ALLOW or DENY for one request against a provider registry, with the same rule
// order and the same reason codes. Decisions are byte-identical to the reference; see
// the README section "Go implementation" for what that is checked against.
package pdp

import (
	"fmt"
	"sort"
	"unicode/utf8"
)

const (
	Allow  = "ALLOW"
	Redact = "REDACT-THEN-ALLOW"
	Deny   = "DENY"

	maxAttestAgeDays = 180
)

var validLabels = map[string]bool{"PUBLIC": true, "INTERNAL": true, "CONFIDENTIAL": true, "RESTRICTED": true, "CUSTOMER_DATA": true}

// Attrs are the six provider fields the decision was made on.
type Attrs struct {
	AttestedOn        string
	ContractSigned    bool
	Region            string
	RetentionDays     Number
	TrainsOnInputs    bool
	ZeroDataRetention bool
}

// Decision is the outcome of Decide. Redacted is nil unless Decision is REDACT-THEN-ALLOW.
type Decision struct {
	Decision string
	Rule     string
	Classes  map[string]int
	Labels   []string
	Attrs    *Attrs
	Redacted *string
}

// Date is a calendar date in the proleptic Gregorian calendar.
type Date struct{ Y, M, D int }

// days counts days since 1970-01-01 (civil-from-days arithmetic, no time package needed).
func (d Date) days() int {
	y, m := d.Y, d.M
	if m <= 2 {
		y--
	}
	era := y / 400
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d.D - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

func leap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

// ParseDate accepts only ASCII YYYY-MM-DD naming a real date in years 1 to 9999.
func ParseDate(s string) (Date, bool) {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return Date{}, false
	}
	n := func(a, b int) int {
		v := 0
		for i := a; i < b; i++ {
			if s[i] < '0' || s[i] > '9' {
				return -1
			}
			v = v*10 + int(s[i]-'0')
		}
		return v
	}
	y, m, d := n(0, 4), n(5, 7), n(8, 10)
	if y < 1 || m < 1 || m > 12 || d < 1 {
		return Date{}, false
	}
	dim := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[m-1]
	if m == 2 && leap(y) {
		dim = 29
	}
	if d > dim {
		return Date{}, false
	}
	return Date{y, m, d}, true
}

func nonBlank(v Value) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, r := range toRunes(s) {
		if !isSpace(r) {
			return true
		}
	}
	return false
}

func validRequest(req Value) bool {
	m, ok := req.(map[string]Value)
	if !ok || len(m) != 4 {
		return false
	}
	for _, k := range [...]string{"app", "labels", "payload", "provider"} {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	if !nonBlank(m["provider"]) || !nonBlank(m["app"]) {
		return false
	}
	if _, ok := m["payload"].(string); !ok {
		return false
	}
	labels, ok := m["labels"].([]Value)
	if !ok {
		return false
	}
	for _, l := range labels {
		s, ok := l.(string)
		if !ok || !validLabels[s] {
			return false
		}
	}
	return true
}

// providerAttrs checks one registry entry the way validate_provider does.
func providerAttrs(entry Value) (*Attrs, bool) {
	m, ok := entry.(map[string]Value)
	if !ok {
		return nil, false
	}
	var a Attrs
	var good [4]bool
	good[0] = setBool(m, "trains_on_inputs", &a.TrainsOnInputs)
	good[1] = setBool(m, "zero_data_retention", &a.ZeroDataRetention)
	good[2] = setBool(m, "contract_signed", &a.ContractSigned)
	days, isInt := m["retention_days"].(Number)
	good[3] = isInt && !days.Float
	region, rok := m["region"].(string)
	att, aok := m["attested_on"].(string)
	if !good[0] || !good[1] || !good[2] || !good[3] || !rok || !aok {
		return nil, false
	}
	a.RetentionDays, a.Region, a.AttestedOn = days, region, att
	if len(days.Lit) > 0 && days.Lit[0] == '-' {
		return nil, false
	}
	if _, ok := ParseDate(att); !ok {
		return nil, false
	}
	if a.ZeroDataRetention && days.Lit != "0" {
		return nil, false
	}
	return &a, true
}

func setBool(m map[string]Value, k string, dst *bool) bool {
	b, ok := m[k].(bool)
	*dst = b
	return ok
}

func result(decision, rule string, classes map[string]int, labels []string, attrs *Attrs, redacted *string) Decision {
	return Decision{Decision: decision, Rule: rule, Classes: classes, Labels: labels, Attrs: attrs, Redacted: redacted}
}

func hasPrefixClass(classes map[string]int, prefix string) bool {
	for c := range classes {
		if len(c) >= len(prefix) && c[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// Decide is the pure policy. The first matching rule wins and anything unclear is DENY.
// request and registry are parsed JSON values (see ParseJSON).
func Decide(request, registry Value, today Date) Decision {
	if !validRequest(request) {
		return result(Deny, "R01_MALFORMED_REQUEST", map[string]int{}, []string{}, nil, nil)
	}
	req := request.(map[string]Value)
	payload := toRunes(req["payload"].(string))
	classes := classify(payload)
	set := map[string]bool{}
	for _, l := range req["labels"].([]Value) {
		set[l.(string)] = true
	}
	for _, l := range textLabels(payload) {
		set[l] = true
	}
	labels := make([]string, 0, len(set))
	for l := range set {
		labels = append(labels, l)
	}
	sort.Strings(labels)

	var providers map[string]Value
	if reg, ok := registry.(map[string]Value); ok {
		providers, _ = reg["providers"].(map[string]Value)
	}
	if providers == nil {
		return result(Deny, "R03_REGISTRY_INVALID", classes, labels, nil, nil)
	}
	entry := providers[req["provider"].(string)]
	if entry == nil {
		return result(Deny, "R02_UNKNOWN_PROVIDER", classes, labels, nil, nil)
	}
	attrs, ok := providerAttrs(entry)
	if !ok {
		return result(Deny, "R03_REGISTRY_INVALID", classes, labels, nil, nil)
	}
	out := func(decision, rule string, redacted *string) Decision {
		return result(decision, rule, classes, labels, attrs, redacted)
	}

	attested, _ := ParseDate(attrs.AttestedOn)
	age := today.days() - attested.days()
	if age < 0 {
		return out(Deny, "R04_ATTESTATION_FUTURE", nil)
	}
	if age > maxAttestAgeDays {
		return out(Deny, "R04_ATTESTATION_STALE", nil)
	}

	secret := hasPrefixClass(classes, "SECRET_")
	pii := hasPrefixClass(classes, "PII_")
	restricted := set["RESTRICTED"]
	confidential := set["CONFIDENTIAL"] || set["RESTRICTED"] || set["CUSTOMER_DATA"]
	internal := set["INTERNAL"]
	sensitive := secret || pii || confidential || internal

	switch {
	case sensitive && attrs.Region != "us" && attrs.Region != "eu":
		return out(Deny, "R05_REGION_NOT_ALLOWED", nil)
	case restricted:
		return out(Deny, "R06_RESTRICTED_NEVER_LEAVES", nil)
	case (secret || confidential) && (attrs.TrainsOnInputs || !attrs.ZeroDataRetention):
		return out(Deny, "R07_CONFIDENTIAL_TO_TRAINING_OR_NON_ZDR", nil)
	case sensitive && !attrs.ContractSigned:
		return out(Deny, "R08_NO_CONTRACT", nil)
	case pii && attrs.TrainsOnInputs:
		return out(Deny, "R09_PII_TO_TRAINING_PROVIDER", nil)
	case internal && attrs.TrainsOnInputs:
		return out(Deny, "R12_INTERNAL_TO_TRAINING_PROVIDER", nil)
	case secret || pii:
		_, cleaned := scan(payload)
		if len(classify(cleaned)) > 0 {
			return out(Deny, "R11_RESIDUAL_AFTER_REDACTION", nil)
		}
		s := fromRunes(cleaned)
		return out(Redact, "R10_REDACT_THEN_ALLOW", &s)
	}
	return out(Allow, "R13_ALLOW", nil)
}

// EvaluateText parses the raw JSON texts and the --now date, decides, and returns the exit
// code of the reference CLI: 0 allow or redact, 1 deny, 2 bad input (err is then set).
func EvaluateText(request, registry, now string) (Decision, int, error) {
	today, ok := ParseDate(now)
	if !ok {
		return Decision{}, 2, fmt.Errorf("--now must be YYYY-MM-DD")
	}
	req, err := ParseJSON(request)
	if err != nil {
		return Decision{}, 2, err
	}
	reg, err := ParseJSON(registry)
	if err != nil {
		return Decision{}, 2, err
	}
	d := Decide(req, reg, today)
	if d.Decision == Deny {
		return d, 1, nil
	}
	return d, 0, nil
}

// Evaluate is EvaluateText for file contents: input that is not valid UTF-8 is bad input.
func Evaluate(request, registry []byte, now string) (Decision, int, error) {
	if !utf8.Valid(request) || !utf8.Valid(registry) {
		return Decision{}, 2, fmt.Errorf("input is not valid UTF-8")
	}
	return EvaluateText(string(request), string(registry), now)
}

// ---------------------------------------------------------------- canonical JSON

// jsonString quotes s as json.dumps(ensure_ascii=True) does: ASCII printable as is, everything
// else as \uXXXX, code points above the BMP as a surrogate pair.
func jsonString(s string) string {
	const hexd = "0123456789abcdef"
	b := []byte{'"'}
	u := func(v rune) {
		b = append(b, '\\', 'u', hexd[v>>12&15], hexd[v>>8&15], hexd[v>>4&15], hexd[v&15])
	}
	for _, r := range toRunes(s) {
		switch {
		case r == '"':
			b = append(b, '\\', '"')
		case r == '\\':
			b = append(b, '\\', '\\')
		case r == '\n':
			b = append(b, '\\', 'n')
		case r == '\r':
			b = append(b, '\\', 'r')
		case r == '\t':
			b = append(b, '\\', 't')
		case r == '\b':
			b = append(b, '\\', 'b')
		case r == '\f':
			b = append(b, '\\', 'f')
		case r >= 0x20 && r <= 0x7E:
			b = append(b, byte(r))
		case r >= 0x10000:
			v := r - 0x10000
			u(0xD800 | v>>10)
			u(0xDC00 | v&0x3FF)
		default:
			u(r)
		}
	}
	return string(append(b, '"'))
}

func boolJSON(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// Canonical is the decision as compact JSON with sorted keys and ASCII-only output, equal to
// json.dumps(decision, sort_keys=True, separators=(",", ":")) in the reference.
func (d Decision) Canonical() string {
	return d.encode(",", ":")
}

// CLIJSON is the four-field line the reference CLI prints, with its default separators.
func (d Decision) CLIJSON() string {
	return "{\"classes\": " + d.classesJSON(", ", ": ") + ", \"decision\": " + jsonString(d.Decision) +
		", \"redacted_payload\": " + d.redactedJSON() + ", \"rule\": " + jsonString(d.Rule) + "}"
}

func (d Decision) redactedJSON() string {
	if d.Redacted == nil {
		return "null"
	}
	return jsonString(*d.Redacted)
}

func (d Decision) classesJSON(item, kv string) string {
	keys := make([]string, 0, len(d.Classes))
	for k := range d.Classes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := "{"
	for i, k := range keys {
		if i > 0 {
			s += item
		}
		s += jsonString(k) + kv + fmt.Sprint(d.Classes[k])
	}
	return s + "}"
}

func (d Decision) encode(item, kv string) string {
	labels := "["
	for i, l := range d.Labels {
		if i > 0 {
			labels += item
		}
		labels += jsonString(l)
	}
	labels += "]"
	attrs := "null"
	if a := d.Attrs; a != nil {
		attrs = "{" + jsonString("attested_on") + kv + jsonString(a.AttestedOn) +
			item + jsonString("contract_signed") + kv + boolJSON(a.ContractSigned) +
			item + jsonString("region") + kv + jsonString(a.Region) +
			item + jsonString("retention_days") + kv + a.RetentionDays.Lit +
			item + jsonString("trains_on_inputs") + kv + boolJSON(a.TrainsOnInputs) +
			item + jsonString("zero_data_retention") + kv + boolJSON(a.ZeroDataRetention) + "}"
	}
	return "{" + jsonString("classes") + kv + d.classesJSON(item, kv) +
		item + jsonString("decision") + kv + jsonString(d.Decision) +
		item + jsonString("labels") + kv + labels +
		item + jsonString("provider_attrs") + kv + attrs +
		item + jsonString("redacted_payload") + kv + d.redactedJSON() +
		item + jsonString("rule") + kv + jsonString(d.Rule) + "}"
}
