package pdp

import (
	"errors"
	"fmt"
)

// A JSON reader with the acceptance rules of the reference (Python json.loads with a hook that
// rejects duplicate object keys and any non-finite constant). encoding/json is not used because
// it accepts duplicate keys, keeps no int versus float distinction, and rejects lone surrogate
// escapes that the reference keeps.
//
// Value is one of: nil, bool, Number, string, []Value, map[string]Value.

type Value = any

// Number is a JSON number. Lit is its text; an integer is stored as Python prints it, so "-0"
// becomes "0". Float is true when the text had a fraction or an exponent.
type Number struct {
	Lit   string
	Float bool
}

const (
	maxIntDigits = 4300 // CPython's default limit on int literals; a longer one is refused
	maxDepth     = 991  // CPython's recursion limit allows about this much nesting
)

var errJSON = errors.New("bad json")

type parser struct {
	s     string
	i     int
	depth int
}

// ParseJSON parses one JSON document.
func ParseJSON(s string) (Value, error) {
	p := &parser{s: s}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("%w: extra data at %d", errJSON, p.i)
	}
	return v, nil
}

func (p *parser) fail(what string) error { return fmt.Errorf("%w: %s at %d", errJSON, what, p.i) }

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value() (Value, error) {
	if p.i >= len(p.s) {
		return nil, p.fail("expecting value")
	}
	switch c := p.s[p.i]; {
	case c == '"':
		return p.str()
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	case p.lit("true"):
		return true, nil
	case p.lit("false"):
		return false, nil
	case p.lit("null"):
		return nil, nil
	}
	return nil, p.fail("expecting value")
}

func (p *parser) lit(w string) bool {
	if len(p.s)-p.i >= len(w) && p.s[p.i:p.i+len(w)] == w {
		p.i += len(w)
		return true
	}
	return false
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return p.fail("nesting too deep")
	}
	return nil
}

func (p *parser) array() (Value, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.i++
	out := []Value{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		p.depth--
		return out, nil
	}
	for {
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.fail("unterminated array")
		}
		c := p.s[p.i]
		p.i++
		if c == ']' {
			p.depth--
			return out, nil
		}
		if c != ',' {
			return nil, p.fail("expecting , or ]")
		}
	}
}

func (p *parser) object() (Value, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	p.i++
	out := map[string]Value{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		p.depth--
		return out, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.fail("expecting property name")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		key := k.(string)
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.fail("expecting :")
		}
		p.i++
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, p.fail("duplicate key")
		}
		out[key] = v
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.fail("unterminated object")
		}
		c := p.s[p.i]
		p.i++
		if c == '}' {
			p.depth--
			return out, nil
		}
		if c != ',' {
			return nil, p.fail("expecting , or }")
		}
	}
}

func hex4(s string, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	var r rune
	for k := 0; k < 4; k++ {
		c := s[i+k]
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

func (p *parser) str() (Value, error) {
	p.i++
	var b []byte
	for {
		if p.i >= len(p.s) {
			return nil, p.fail("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(b), nil
		case c < 0x20:
			return nil, p.fail("control character in string")
		case c != '\\':
			b = append(b, c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.s) {
			return nil, p.fail("unterminated string")
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			b = append(b, e)
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			r, ok := hex4(p.s, p.i)
			if !ok {
				return nil, p.fail("bad \\u escape")
			}
			p.i += 4
			if r >= 0xD800 && r <= 0xDBFF && p.i+6 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
				lo, ok := hex4(p.s, p.i+2)
				if !ok {
					return nil, p.fail("bad \\u escape")
				}
				if lo >= 0xDC00 && lo <= 0xDFFF {
					r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
					p.i += 6
				}
			}
			b = appendRune(b, r)
		default:
			return nil, p.fail("bad escape")
		}
	}
}

func (p *parser) number() (Value, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) {
		return nil, p.fail("expecting value")
	}
	intStart := p.i
	switch c := p.s[p.i]; {
	case c == '0':
		p.i++
	case c >= '1' && c <= '9':
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	default:
		return nil, p.fail("expecting value")
	}
	intEnd := p.i
	float := false
	if p.i+1 < len(p.s) && p.s[p.i] == '.' && p.s[p.i+1] >= '0' && p.s[p.i+1] <= '9' {
		float = true
		p.i++
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		j := p.i + 1
		if j < len(p.s) && (p.s[j] == '+' || p.s[j] == '-') {
			j++
		}
		if j < len(p.s) && p.s[j] >= '0' && p.s[j] <= '9' {
			for j < len(p.s) && p.s[j] >= '0' && p.s[j] <= '9' {
				j++
			}
			float = true
			p.i = j
		}
	}
	lit := p.s[start:p.i]
	if float {
		return Number{Lit: lit, Float: true}, nil
	}
	if intEnd-intStart > maxIntDigits {
		return nil, p.fail("integer literal too long")
	}
	if lit == "-0" {
		lit = "0"
	}
	return Number{Lit: lit}, nil
}
