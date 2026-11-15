package pdp

import "sort"

// Strings in this package are UTF-8 with one extension: a lone UTF-16 surrogate (which a JSON
// text can name with \uD800 and which Python keeps as a str code point) is held as its
// three-byte generalized form. toRunes and fromRunes are the only places that know this.

const runeError = 0xFFFD

func toRunes(s string) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		b := s[i]
		switch {
		case b < 0x80:
			out = append(out, rune(b))
			i++
		case b >= 0xC2 && b <= 0xDF && i+1 < len(s) && s[i+1]&0xC0 == 0x80:
			out = append(out, rune(b&0x1F)<<6|rune(s[i+1]&0x3F))
			i += 2
		case b >= 0xE0 && b <= 0xEF && i+2 < len(s) && s[i+1]&0xC0 == 0x80 && s[i+2]&0xC0 == 0x80:
			r := rune(b&0x0F)<<12 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F)
			if r < 0x800 {
				out = append(out, runeError)
			} else {
				out = append(out, r)
			}
			i += 3
		case b >= 0xF0 && b <= 0xF4 && i+3 < len(s) && s[i+1]&0xC0 == 0x80 && s[i+2]&0xC0 == 0x80 && s[i+3]&0xC0 == 0x80:
			r := rune(b&0x07)<<18 | rune(s[i+1]&0x3F)<<12 | rune(s[i+2]&0x3F)<<6 | rune(s[i+3]&0x3F)
			if r < 0x10000 || r > 0x10FFFF {
				out = append(out, runeError)
			} else {
				out = append(out, r)
			}
			i += 4
		default:
			out = append(out, runeError)
			i++
		}
	}
	return out
}

func appendRune(b []byte, r rune) []byte {
	switch {
	case r < 0x80:
		return append(b, byte(r))
	case r < 0x800:
		return append(b, 0xC0|byte(r>>6), 0x80|byte(r&0x3F))
	case r < 0x10000:
		return append(b, 0xE0|byte(r>>12), 0x80|byte(r>>6&0x3F), 0x80|byte(r&0x3F))
	default:
		return append(b, 0xF0|byte(r>>18), 0x80|byte(r>>12&0x3F), 0x80|byte(r>>6&0x3F), 0x80|byte(r&0x3F))
	}
}

func fromRunes(rs []rune) string {
	b := make([]byte, 0, len(rs))
	for _, r := range rs {
		b = appendRune(b, r)
	}
	return string(b)
}

func inRanges(r rune, rs []rng) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= r })
	return i < len(rs) && rs[i].lo <= r
}

func isCf(r rune) bool    { return inRanges(r, cfRanges) }
func isSpace(r rune) bool { return inRanges(r, spaceRanges) }

// isWord is Python's \w for str patterns.
func isWord(r rune) bool { return r == '_' || inRanges(r, alnumRanges) }

// decimalValue is the value of r when it is a decimal digit (Python's \d), else -1.
func decimalValue(r rune) int {
	i := sort.Search(len(decimalZeros), func(i int) bool { return decimalZeros[i] > r })
	if i == 0 {
		return -1
	}
	if d := r - decimalZeros[i-1]; d >= 0 && d <= 9 {
		return int(d)
	}
	return -1
}

func isDigit(r rune) bool { return decimalValue(r) >= 0 }

func isAsciiDigit(r rune) bool { return r >= '0' && r <= '9' }

func isAsciiAlpha(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// boundary is Python's \b at position i of text.
func boundary(text []rune, i int) bool {
	left := i > 0 && isWord(text[i-1])
	right := i < len(text) && isWord(text[i])
	return left != right
}
