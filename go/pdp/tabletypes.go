package pdp

// Element types of the generated tables in tables_gen.go.

type rng struct{ lo, hi rune }

type cccRange struct {
	lo, hi rune
	c      uint8
}

// nfkdEntry: the full NFKD of cp is nfkdData[off : off+n].
type nfkdEntry struct {
	cp     rune
	off, n int
}

// compPair: primary composite c of the sequence a, b.
type compPair struct{ a, b, c rune }
