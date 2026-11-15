package pdp

import "sort"

// NFKC written out from the tables in tables_gen.go (the Go standard library has no
// normalization package): full compatibility decomposition, canonical reordering by combining
// class, then canonical composition as in Unicode Standard Annex 15.

const (
	hangulSBase  = 0xAC00
	hangulLBase  = 0x1100
	hangulVBase  = 0x1161
	hangulTBase  = 0x11A7
	hangulLCount = 19
	hangulVCount = 21
	hangulTCount = 28
	hangulNCount = hangulVCount * hangulTCount
	hangulSCount = hangulLCount * hangulNCount
)

func ccc(r rune) uint8 {
	i := sort.Search(len(cccRanges), func(i int) bool { return cccRanges[i].hi >= r })
	if i < len(cccRanges) && cccRanges[i].lo <= r {
		return cccRanges[i].c
	}
	return 0
}

func appendDecomposed(out []rune, r rune) []rune {
	if r >= hangulSBase && r < hangulSBase+hangulSCount {
		s := r - hangulSBase
		out = append(out, hangulLBase+s/hangulNCount, hangulVBase+s%hangulNCount/hangulTCount)
		if t := s % hangulTCount; t != 0 {
			out = append(out, hangulTBase+t)
		}
		return out
	}
	i := sort.Search(len(nfkdIndex), func(i int) bool { return nfkdIndex[i].cp >= r })
	if i < len(nfkdIndex) && nfkdIndex[i].cp == r {
		e := nfkdIndex[i]
		return append(out, nfkdData[e.off:e.off+e.n]...)
	}
	return append(out, r)
}

// reorder sorts each run of non-starters by combining class; the sort is stable.
func reorder(rs []rune) {
	for i := 0; i < len(rs); {
		if ccc(rs[i]) == 0 {
			i++
			continue
		}
		j := i
		for j < len(rs) && ccc(rs[j]) != 0 {
			j++
		}
		run := rs[i:j]
		sort.SliceStable(run, func(a, b int) bool { return ccc(run[a]) < ccc(run[b]) })
		i = j
	}
}

func composePair(a, b rune) (rune, bool) {
	if a >= hangulLBase && a < hangulLBase+hangulLCount && b >= hangulVBase && b < hangulVBase+hangulVCount {
		return hangulSBase + ((a-hangulLBase)*hangulVCount+(b-hangulVBase))*hangulTCount, true
	}
	if a >= hangulSBase && a < hangulSBase+hangulSCount && (a-hangulSBase)%hangulTCount == 0 &&
		b > hangulTBase && b < hangulTBase+hangulTCount {
		return a + (b - hangulTBase), true
	}
	i := sort.Search(len(compPairs), func(i int) bool {
		p := compPairs[i]
		return p.a > a || p.a == a && p.b >= b
	})
	if i < len(compPairs) && compPairs[i].a == a && compPairs[i].b == b {
		return compPairs[i].c, true
	}
	return 0, false
}

func compose(rs []rune) []rune {
	if len(rs) == 0 {
		return rs
	}
	out := make([]rune, 0, len(rs))
	out = append(out, rs[0])
	starter := 0
	last := int(ccc(rs[0]))
	if last != 0 {
		last = 256 // a leading non-starter blocks nothing but can never be composed into
	}
	for _, ch := range rs[1:] {
		cl := int(ccc(ch))
		if comp, ok := composePair(out[starter], ch); ok && (last < cl || last == 0) {
			out[starter] = comp
			continue
		}
		if cl == 0 {
			starter = len(out)
		}
		last = cl
		out = append(out, ch)
	}
	return out
}

// nfkc returns the NFKC form of rs.
func nfkc(rs []rune) []rune {
	d := make([]rune, 0, len(rs))
	for _, r := range rs {
		d = appendDecomposed(d, r)
	}
	reorder(d)
	return compose(d)
}

// normalize is NFKC followed by dropping every format character (category Cf), exactly the
// text the patterns run on.
func normalize(rs []rune) []rune {
	c := nfkc(rs)
	out := c[:0:0]
	for _, r := range c {
		if !isCf(r) {
			out = append(out, r)
		}
	}
	return out
}
