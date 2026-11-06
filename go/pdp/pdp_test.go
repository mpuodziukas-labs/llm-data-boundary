package pdp

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const (
	casesDir     = "../../cases"
	parityFile   = "../testdata/parity.jsonl"
	normalizeSet = "../testdata/normalize.jsonl"
	minParity    = 2000
)

// TestCases runs every case folder of the repository (not a copy) through the Go decision point
// and compares exit code, decision, rule, class counts and redacted text with expected.json.
func TestCases(t *testing.T) {
	entries, err := os.ReadDir(casesDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) != 28 {
		t.Fatalf("expected 28 case folders, found %d", len(names))
	}
	matched := 0
	for _, name := range names {
		dir := filepath.Join(casesDir, name)
		var want struct {
			Exit     int            `json:"exit"`
			Now      string         `json:"now"`
			Decision *string        `json:"decision"`
			Rule     *string        `json:"rule"`
			Classes  map[string]int `json:"classes"`
			Redacted *string        `json:"redacted_payload"`
		}
		raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		req, err := os.ReadFile(filepath.Join(dir, "request.json"))
		if err != nil {
			t.Fatal(err)
		}
		reg, err := os.ReadFile(filepath.Join(dir, "registry.json"))
		if err != nil {
			t.Fatal(err)
		}
		d, exit, _ := Evaluate(req, reg, want.Now)
		ok := exit == want.Exit
		if want.Exit != 2 {
			ok = ok && d.Decision == *want.Decision && d.Rule == *want.Rule && sameClasses(d.Classes, want.Classes) &&
				sameText(d.Redacted, want.Redacted)
		}
		if ok {
			matched++
		} else {
			t.Errorf("case %s: exit=%d decision=%q rule=%q classes=%v", name, exit, d.Decision, d.Rule, d.Classes)
		}
	}
	t.Logf("cases %d/%d", matched, len(names))
	if matched != len(names) {
		t.Fatalf("cases %d/%d", matched, len(names))
	}
}

func sameClasses(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func sameText(got *string, want *string) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want
}

// lines streams a JSONL corpus; every line is parsed with the package's own JSON parser.
func lines(t *testing.T, path string, fn func(rec map[string]Value)) int {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	n := 0
	for sc.Scan() {
		v, err := ParseJSON(sc.Text())
		if err != nil {
			t.Fatalf("%s line %d: %v", path, n+1, err)
		}
		rec, ok := v.(map[string]Value)
		if !ok {
			t.Fatalf("%s line %d: not an object", path, n+1)
		}
		fn(rec)
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestParity is the differential test: the Python decision point wrote testdata/parity.jsonl;
// the Go canonical JSON must equal it byte for byte, and bad input must be refused alike.
func TestParity(t *testing.T) {
	matched, shown := 0, 0
	total := lines(t, parityFile, func(rec map[string]Value) {
		id, _ := rec["id"].(Number)
		req, _ := rec["request"].(string)
		reg, _ := rec["registry"].(string)
		now, _ := rec["now"].(string)
		var want *string
		if w, ok := rec["want"].(string); ok {
			want = &w
		}
		d, exit, err := EvaluateText(req, reg, now)
		var got *string
		if err == nil {
			c := d.Canonical()
			got = &c
		}
		if sameText(got, want) && (err != nil) == (exit == 2) {
			matched++
			return
		}
		if shown < 5 {
			shown++
			t.Errorf("record %s differs\n got: %v\nwant: %v\n req: %.300q", id.Lit, deref(got), deref(want), req)
		}
	})
	t.Logf("parity %d/%d", matched, total)
	if total < minParity {
		t.Fatalf("parity corpus has %d records, need at least %d", total, minParity)
	}
	if matched != total {
		t.Fatalf("parity %d/%d", matched, total)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<bad input>"
	}
	return *s
}

// TestNormalizeParity checks NFKC plus format-character stripping against boundary.normalize.
func TestNormalizeParity(t *testing.T) {
	matched, shown := 0, 0
	total := lines(t, normalizeSet, func(rec map[string]Value) {
		in, _ := rec["in"].(string)
		out, _ := rec["out"].(string)
		if got := fromRunes(normalize(toRunes(in))); got == out {
			matched++
		} else if shown < 5 {
			shown++
			t.Errorf("normalize(%+q) = %+q, want %+q", in, got, out)
		}
	})
	t.Logf("normalize %d/%d", matched, total)
	if total < 1000 || matched != total {
		t.Fatalf("normalize %d/%d", matched, total)
	}
}
