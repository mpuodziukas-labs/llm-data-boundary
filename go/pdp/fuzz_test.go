package pdp

import "testing"

func fuzzRegistry(zdr bool, region string) Value {
	days := Number{Lit: "0"}
	if !zdr {
		days = Number{Lit: "30"}
	}
	return map[string]Value{"providers": map[string]Value{"p": map[string]Value{
		"trains_on_inputs":    false,
		"zero_data_retention": zdr,
		"retention_days":      days,
		"region":              region,
		"contract_signed":     true,
		"attested_on":         "2026-10-01",
	}}}
}

// FuzzDecide: for any payload, provider, label and registry shape the decision point must not
// panic, must give the same answer twice, and must fail closed on anything it does not know:
// a label outside the known set is a deny (R01), an unlisted provider is a deny (R02).
func FuzzDecide(f *testing.F) {
	f.Add("hello", "p", "PUBLIC", true, "us")
	f.Add("card 4111 1111 1111 1111", "p", "INTERNAL", false, "eu")
	f.Add("ssn 123-45-6789", "p", "UNKNOWN_CLASS", true, "us")
	f.Add("AKIAIOSFODNN7EXAMPLE", "other", "RESTRICTED", true, "apac")
	f.Add("\xff\xfe broken \xed\xa0\x80", "p", "", true, "us")
	f.Add("S​SN CONFIDENTIAL", "p", "CUSTOMER_DATA", false, "us")
	today := Date{2026, 11, 1}
	f.Fuzz(func(t *testing.T, payload, provider, label string, zdr bool, region string) {
		req := map[string]Value{
			"provider": provider,
			"payload":  payload,
			"labels":   []Value{label},
			"app":      "a",
		}
		reg := fuzzRegistry(zdr, region)
		a := Decide(req, reg, today)
		b := Decide(req, reg, today)
		if a.Canonical() != b.Canonical() {
			t.Fatalf("not deterministic: %s vs %s", a.Canonical(), b.Canonical())
		}
		known := map[string]bool{"PUBLIC": true, "INTERNAL": true, "CONFIDENTIAL": true, "RESTRICTED": true, "CUSTOMER_DATA": true}
		if !known[label] && (a.Decision != "DENY" || a.Rule != "R01_MALFORMED_REQUEST") {
			t.Fatalf("unknown class %q not denied: %s", label, a.Canonical())
		}
		if provider != "p" && a.Decision != "DENY" {
			t.Fatalf("unlisted provider %q not denied: %s", provider, a.Canonical())
		}
		if a.Decision != "ALLOW" && a.Decision != "REDACT-THEN-ALLOW" && a.Decision != "DENY" {
			t.Fatalf("decision outside the closed set: %q", a.Decision)
		}
	})
}
