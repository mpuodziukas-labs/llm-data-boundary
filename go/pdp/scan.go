package pdp

import (
	"math"
	"sort"
)

// The reference matches with Python regular expressions, whose Unicode digit, space and word
// classes, look-behind and look-ahead have no equivalent in Go's RE2. Each pattern below is a
// hand-written matcher that returns the same span the reference regex would claim at a start
// position. A pattern pass scans left to right, takes the first start that matches, and
// continues after the end of that span whether or not the validator accepts it.

const (
	clsPrivateKey = "SECRET_PRIVATE_KEY"
	clsAWS        = "SECRET_AWS_KEY"
	clsBearer     = "SECRET_BEARER"
	clsCard       = "PII_CARD"
	clsSSN        = "PII_SSN"
	clsEmail      = "PII_EMAIL"
	clsPhone      = "PII_PHONE"
	clsEntropy    = "SECRET_ENTROPY"

	entropyMinLen    = 24
	entropyThreshold = 4.0
)

type matcher func(text []rune, i int) (end int, ok bool)

type pattern struct {
	class string
	// next returns the first match starting at or after pos, as [start, end).
	next  func(text []rune, pos int) (start, end int, ok bool)
	check func(text []rune, start, end int) bool
}

func hasLit(text []rune, i int, lit string) bool {
	rs := []rune(lit)
	if i < 0 || i+len(rs) > len(text) {
		return false
	}
	for k, r := range rs {
		if text[i+k] != r {
			return false
		}
	}
	return true
}

// atEach turns an anchored matcher into a leftmost search.
func atEach(m matcher) func(text []rune, pos int) (int, int, bool) {
	return func(text []rune, pos int) (int, int, bool) {
		for i := pos; i < len(text); i++ {
			if end, ok := m(text, i); ok {
				return i, end, true
			}
		}
		return 0, 0, false
	}
}

// -----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----
func matchPrivateKey(text []rune, i int) (int, bool) {
	if !hasLit(text, i, "-----BEGIN ") {
		return 0, false
	}
	j := i + len("-----BEGIN ")
	k := j
	for k < len(text) && text[k] >= 'A' && text[k] <= 'Z' {
		k++
	}
	if k > j && k < len(text) && text[k] == ' ' && hasLit(text, k+1, "PRIVATE KEY-----") {
		return k + 1 + len("PRIVATE KEY-----"), true
	}
	if hasLit(text, j, "PRIVATE KEY-----") {
		return j + len("PRIVATE KEY-----"), true
	}
	return 0, false
}

func isUpperDigit(r rune) bool { return r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' }

// \b(?:AKIA|ASIA)[0-9A-Z]{16}\b
func matchAWS(text []rune, i int) (int, bool) {
	if !boundary(text, i) || !(hasLit(text, i, "AKIA") || hasLit(text, i, "ASIA")) {
		return 0, false
	}
	end := i + 4 + 16
	if end > len(text) {
		return 0, false
	}
	for k := i + 4; k < end; k++ {
		if !isUpperDigit(text[k]) {
			return 0, false
		}
	}
	if !boundary(text, end) {
		return 0, false
	}
	return end, true
}

func isBearerChar(r rune) bool {
	return isAsciiAlpha(r) || isAsciiDigit(r) || r == '.' || r == '_' || r == '~' || r == '+' || r == '/' || r == '-'
}

// \b[Bb]earer\s+[A-Za-z0-9._~+/\-]{16,}=*
func matchBearer(text []rune, i int) (int, bool) {
	if !boundary(text, i) || i >= len(text) || (text[i] != 'B' && text[i] != 'b') || !hasLit(text, i+1, "earer") {
		return 0, false
	}
	j := i + 6
	s := j
	for j < len(text) && isSpace(text[j]) {
		j++
	}
	if j == s {
		return 0, false
	}
	t := j
	for j < len(text) && isBearerChar(text[j]) {
		j++
	}
	if j-t < 16 {
		return 0, false
	}
	for j < len(text) && text[j] == '=' {
		j++
	}
	return j, true
}

func isCardSep(r rune) bool { return r == ' ' || r == '-' }

// (?<!\d)(?:\d[ -]?){12,18}\d(?!\d)
//
// After each digit a single separator is taken if present, because skipping it can never let
// the next group or the final digit match. So the digits that can belong to the match form one
// forced chain from the start; the longest prefix of 13 to 19 digits whose last digit is not
// followed by another digit wins, which is what greedy repetition with backtracking yields.
func matchCard(text []rune, i int) (int, bool) {
	if i >= len(text) || !isDigit(text[i]) || (i > 0 && isDigit(text[i-1])) {
		return 0, false
	}
	var pos [19]int
	m := 0
	for j := i; m < 19; {
		pos[m] = j
		m++
		j++
		if j < len(text) && isCardSep(text[j]) {
			j++
		}
		if j >= len(text) || !isDigit(text[j]) {
			break
		}
	}
	for t := m; t >= 13; t-- {
		end := pos[t-1] + 1
		if end >= len(text) || !isDigit(text[end]) {
			return end, true
		}
	}
	return 0, false
}

func cardDigits(text []rune, start, end int) []int {
	var ds []int
	for _, r := range text[start:end] {
		if v := decimalValue(r); v >= 0 {
			ds = append(ds, v)
		}
	}
	return ds
}

func checkCard(text []rune, start, end int) bool {
	ds := cardDigits(text, start, end)
	if len(ds) < 13 || len(ds) > 19 {
		return false
	}
	total := 0
	for k := 0; k < len(ds); k++ {
		d := ds[len(ds)-1-k]
		if k%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
	}
	return total%10 == 0
}

func digitsAt(text []rune, i, n int) bool {
	if i+n > len(text) {
		return false
	}
	for k := 0; k < n; k++ {
		if !isDigit(text[i+k]) {
			return false
		}
	}
	return true
}

// (?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)
func matchSSN(text []rune, i int) (int, bool) {
	if i > 0 && isDigit(text[i-1]) {
		return 0, false
	}
	if !digitsAt(text, i, 3) || i+3 >= len(text) || text[i+3] != '-' || !digitsAt(text, i+4, 2) ||
		i+6 >= len(text) || text[i+6] != '-' || !digitsAt(text, i+7, 4) {
		return 0, false
	}
	end := i + 11
	if end < len(text) && isDigit(text[end]) {
		return 0, false
	}
	return end, true
}

func checkSSN(text []rune, start, end int) bool {
	area, group, serial := string(text[start:start+3]), string(text[start+4:start+6]), string(text[start+7:end])
	if area == "000" || area == "666" || text[start] == '9' {
		return false
	}
	return group != "00" && serial != "0000"
}

func isLocalChar(r rune) bool {
	return isAsciiAlpha(r) || isAsciiDigit(r) || r == '.' || r == '_' || r == '%' || r == '+' || r == '-'
}

func isDomainChar(r rune) bool { return isAsciiAlpha(r) || isAsciiDigit(r) || r == '.' || r == '-' }

// emailDomainEnd matches [A-Za-z0-9.\-]+\.[A-Za-z]{2,} starting right after the at sign. The
// domain run is greedy and gives back characters until a dot is followed by two or more
// letters, so the last such dot inside the run decides the end.
func emailDomainEnd(text []rune, at int) (int, bool) {
	q := at + 1
	for q < len(text) && isDomainChar(text[q]) {
		q++
	}
	for k := q - 1; k >= at+2; k-- {
		if text[k] != '.' {
			continue
		}
		r := k + 1
		for r < len(text) && isAsciiAlpha(text[r]) {
			r++
		}
		if r-(k+1) >= 2 {
			return r, true
		}
	}
	return 0, false
}

// [A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}
func nextEmail(text []rune, pos int) (int, int, bool) {
	for i := pos; i < len(text); {
		if !isLocalChar(text[i]) {
			i++
			continue
		}
		e := i
		for e < len(text) && isLocalChar(text[e]) {
			e++
		}
		if e < len(text) && text[e] == '@' {
			if end, ok := emailDomainEnd(text, e); ok {
				return i, end, true
			}
		}
		i = e
	}
	return 0, 0, false
}

func isPhoneSep(r rune) bool { return r == ' ' || r == '.' || r == '-' }

// (?:\(\d{3}\)|\d{3})[ .\-]?\d{3}[ .\-]\d{4}(?!\d)
func phoneBody(text []rune, j int) (int, bool) {
	if j < len(text) && text[j] == '(' {
		if !digitsAt(text, j+1, 3) || j+4 >= len(text) || text[j+4] != ')' {
			return 0, false
		}
		j += 5
	} else {
		if !digitsAt(text, j, 3) {
			return 0, false
		}
		j += 3
	}
	if j < len(text) && isPhoneSep(text[j]) {
		j++
	}
	if !digitsAt(text, j, 3) {
		return 0, false
	}
	j += 3
	if j >= len(text) || !isPhoneSep(text[j]) {
		return 0, false
	}
	j++
	if !digitsAt(text, j, 4) {
		return 0, false
	}
	j += 4
	if j < len(text) && isDigit(text[j]) {
		return 0, false
	}
	return j, true
}

// (?<!\d)(?:\+?1[ .\-]?)?BODY: the optional country prefix is tried first, then the bare body.
func matchPhone(text []rune, i int) (int, bool) {
	if i > 0 && isDigit(text[i-1]) {
		return 0, false
	}
	j := i
	if j < len(text) && text[j] == '+' {
		j++
	}
	if j < len(text) && text[j] == '1' {
		j++
		if j < len(text) && isPhoneSep(text[j]) {
			j++
		}
		if end, ok := phoneBody(text, j); ok {
			return end, true
		}
	}
	return phoneBody(text, i)
}

func isEntropyChar(r rune) bool {
	return isAsciiAlpha(r) || isAsciiDigit(r) || r == '+' || r == '/' || r == '_' || r == '-'
}

// [A-Za-z0-9+/_\-]{24,}: a pass can only start a match at the head of a maximal run.
func nextEntropy(text []rune, pos int) (int, int, bool) {
	for i := pos; i < len(text); {
		if !isEntropyChar(text[i]) {
			i++
			continue
		}
		e := i
		for e < len(text) && isEntropyChar(text[e]) {
			e++
		}
		if e-i >= entropyMinLen {
			return i, e, true
		}
		i = e
	}
	return 0, 0, false
}

func shannon(tok []rune) float64 {
	n := float64(len(tok))
	counts := map[rune]int{}
	var order []rune
	for _, r := range tok {
		if counts[r] == 0 {
			order = append(order, r)
		}
		counts[r]++
	}
	sort.Slice(order, func(a, b int) bool { return order[a] < order[b] })
	sum := 0.0
	for _, r := range order {
		p := float64(counts[r]) / n
		sum += p * math.Log2(p)
	}
	return -sum
}

func checkEntropy(text []rune, start, end int) bool {
	tok := text[start:end]
	digit, alpha := false, false
	for _, r := range tok {
		if isAsciiDigit(r) {
			digit = true
		} else if isAsciiAlpha(r) {
			alpha = true
		}
	}
	return digit && alpha && shannon(tok) >= entropyThreshold
}

var patterns = []pattern{
	{clsPrivateKey, atEach(matchPrivateKey), nil},
	{clsAWS, atEach(matchAWS), nil},
	{clsBearer, atEach(matchBearer), nil},
	{clsCard, atEach(matchCard), checkCard},
	{clsSSN, atEach(matchSSN), checkSSN},
	{clsEmail, nextEmail, nil},
	{clsPhone, atEach(matchPhone), nil},
	{clsEntropy, nextEntropy, checkEntropy},
}

// scan normalizes text and returns the class counts and the text with every accepted match
// replaced by [REDACTED:CLASS]. Patterns run in order, each on the output of the one before.
func scan(src []rune) (map[string]int, []rune) {
	text := normalize(src)
	counts := map[string]int{}
	for _, p := range patterns {
		var out []rune
		pos := 0
		for {
			start, end, ok := p.next(text, pos)
			if !ok {
				break
			}
			out = append(out, text[pos:start]...)
			if p.check == nil || p.check(text, start, end) {
				counts[p.class]++
				out = append(out, []rune("[REDACTED:"+p.class+"]")...)
			} else {
				out = append(out, text[start:end]...)
			}
			pos = end
		}
		text = append(out, text[pos:]...)
	}
	return counts, text
}

func classify(src []rune) map[string]int {
	c, _ := scan(src)
	return c
}

func foldEq(r rune, lower byte) bool {
	return r == rune(lower) || r == rune(lower)-'a'+'A'
}

func hasFold(text []rune, i int, lit string) bool {
	if i+len(lit) > len(text) {
		return false
	}
	for k := 0; k < len(lit); k++ {
		if !foldEq(text[i+k], lit[k]) {
			return false
		}
	}
	return true
}

// textLabels finds the words CONFIDENTIAL, INTERNAL, RESTRICTED (exact case) and the phrase
// customer data (any case, one of space, underscore, hyphen between), each between word
// boundaries. A match is whole words, so matches cannot overlap and finding each label on its
// own is the same as the reference's findall.
func textLabels(src []rune) []string {
	text := normalize(src)
	found := map[string]bool{}
	for i := 0; i < len(text); i++ {
		if !boundary(text, i) {
			continue
		}
		for _, w := range [...]string{"CONFIDENTIAL", "INTERNAL", "RESTRICTED"} {
			if hasLit(text, i, w) && boundary(text, i+len(w)) {
				found[w] = true
			}
		}
		if hasFold(text, i, "customer") && i+8 < len(text) &&
			(text[i+8] == ' ' || text[i+8] == '_' || text[i+8] == '-') &&
			hasFold(text, i+9, "data") && boundary(text, i+13) {
			found["CUSTOMER_DATA"] = true
		}
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
