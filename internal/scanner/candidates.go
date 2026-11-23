package scanner

import (
	"math/big"
	"math/rand"
	"strings"
)

var (
	bigOne = big.NewInt(1)
)

// labelStream yields every label of a given length exactly once. It uses an
// affine permutation modulo len(alphabet)^length, so memory stays O(1) even
// for huge label spaces (the scan stops long before exhausting 4-5 chars).
type labelStream struct {
	alphabet   string
	prefix     string
	length     int
	total      *big.Int
	step       *big.Int
	start      *big.Int
	index      *big.Int
	sequential bool
	hyphen     bool
}

func newLabelStream(
	length int,
	alphabet, prefix string,
	rng *rand.Rand,
	sequential bool,
) *labelStream {
	suffixLength := length - len(prefix)
	if suffixLength < 1 {
		return &labelStream{
			alphabet: alphabet,
			prefix:   prefix,
			length:   0,
			total:    big.NewInt(0),
			index:    big.NewInt(0),
		}
	}
	total := new(big.Int).Exp(
		big.NewInt(int64(len(alphabet))), big.NewInt(int64(suffixLength)), nil,
	)
	stream := &labelStream{
		alphabet:   alphabet,
		prefix:     prefix,
		length:     suffixLength,
		total:      total,
		index:      big.NewInt(0),
		sequential: sequential || total.Cmp(bigOne) <= 0,
		hyphen:     strings.ContainsRune(alphabet, '-'),
	}
	if stream.sequential {
		return stream
	}

	maxStep := new(big.Int).Sub(total, bigOne)
	for {
		step := randomBelow(rng, maxStep)
		step.Add(step, bigOne)
		if new(big.Int).GCD(nil, nil, step, total).Cmp(bigOne) == 0 {
			stream.step = step
			break
		}
	}
	stream.start = randomBelow(rng, total)
	return stream
}

func (s *labelStream) next() (string, bool) {
	for s.index.Cmp(s.total) < 0 {
		position := new(big.Int)
		if s.sequential {
			position.Set(s.index)
		} else {
			position.Mul(s.index, s.step)
			position.Add(position, s.start)
			position.Mod(position, s.total)
		}
		s.index.Add(s.index, bigOne)

		label := s.prefix + decodeLabel(position, s.alphabet, s.length)
		if s.hyphen && (strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-")) {
			continue
		}
		return label, true
	}
	return "", false
}

func decodeLabel(index *big.Int, alphabet string, length int) string {
	buf := make([]byte, length)
	base := big.NewInt(int64(len(alphabet)))
	current := new(big.Int).Set(index)
	quotient := new(big.Int)
	remainder := new(big.Int)
	for i := length - 1; i >= 0; i-- {
		quotient.QuoRem(current, base, remainder)
		buf[i] = alphabet[remainder.Int64()]
		current.Set(quotient)
	}
	return string(buf)
}

func randomBelow(rng *rand.Rand, n *big.Int) *big.Int {
	if n.Sign() <= 0 {
		return new(big.Int)
	}
	buf := make([]byte, (n.BitLen()+7)/8)
	_, _ = rng.Read(buf)
	value := new(big.Int).SetBytes(buf)
	return value.Mod(value, n)
}

type tldStream struct {
	tld    string
	labels *labelStream
}

// domainStreams round-robins between TLDs so hits are spread across
// extensions instead of exhausting one TLD at a time.
type domainStreams struct {
	active []tldStream
	cursor int
}

func newDomainStreams(
	level int,
	tlds []string,
	cfg *Config,
	rng *rand.Rand,
) *domainStreams {
	prefix := cfg.Sequential
	sequential := prefix != ""
	streams := make([]tldStream, 0, len(tlds))
	for _, tld := range tlds {
		labelLength := level - len(tld)
		if labelLength < cfg.MinLabel || labelLength > maxDNSLabel {
			continue
		}
		if labelLength <= len(prefix) {
			continue
		}
		streams = append(streams, tldStream{
			tld: tld,
			labels: newLabelStream(
				labelLength, cfg.Alphabet, prefix, rng, sequential,
			),
		})
	}
	if !sequential {
		rng.Shuffle(len(streams), func(i, j int) {
			streams[i], streams[j] = streams[j], streams[i]
		})
	}
	return &domainStreams{active: streams}
}

func (d *domainStreams) next() (string, bool) {
	for len(d.active) > 0 {
		if d.cursor >= len(d.active) {
			d.cursor = 0
		}
		stream := &d.active[d.cursor]
		label, ok := stream.labels.next()
		if !ok {
			d.active = append(d.active[:d.cursor], d.active[d.cursor+1:]...)
			if d.cursor >= len(d.active) {
				d.cursor = 0
			}
			continue
		}
		d.cursor++
		return label + "." + stream.tld, true
	}
	return "", false
}
