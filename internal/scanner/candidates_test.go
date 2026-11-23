package scanner

import (
	"math/big"
	"math/rand"
	"testing"
)

func TestDecodeLabel(t *testing.T) {
	tests := []struct {
		index    int64
		alphabet string
		length   int
		want     string
	}{
		{0, "ab", 2, "aa"},
		{1, "ab", 2, "ab"},
		{2, "ab", 2, "ba"},
		{3, "ab", 2, "bb"},
		{25, "abcdefghijklmnopqrstuvwxyz", 1, "z"},
	}
	for _, test := range tests {
		got := decodeLabel(big.NewInt(test.index), test.alphabet, test.length)
		if got != test.want {
			t.Errorf("decodeLabel(%d, %q, %d) = %q, want %q",
				test.index, test.alphabet, test.length, got, test.want)
		}
	}
}

func collectLabels(stream *labelStream) []string {
	var labels []string
	for {
		label, ok := stream.next()
		if !ok {
			return labels
		}
		labels = append(labels, label)
	}
}

func TestLabelStreamSequential(t *testing.T) {
	stream := newLabelStream(2, "ab", "", rand.New(rand.NewSource(1)), true)
	got := collectLabels(stream)
	want := []string{"aa", "ab", "ba", "bb"}
	if len(got) != len(want) {
		t.Fatalf("got %d labels, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("label %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLabelStreamRandomCoversEveryLabel(t *testing.T) {
	stream := newLabelStream(2, "ab", "", rand.New(rand.NewSource(7)), false)
	seen := make(map[string]bool)
	for _, label := range collectLabels(stream) {
		if seen[label] {
			t.Fatalf("duplicate label %q", label)
		}
		seen[label] = true
	}
	if len(seen) != 4 {
		t.Fatalf("got %d unique labels, want 4", len(seen))
	}
}

func TestDomainStreamsRoundRobin(t *testing.T) {
	cfg := &Config{MinLabel: 1, Alphabet: "ab", Sequential: "a"}
	streams := newDomainStreams(4, []string{"a", "b"}, cfg, rand.New(rand.NewSource(1)))

	first, ok := streams.next()
	if !ok || first != "aaa.a" {
		t.Fatalf("first domain = %q, want aa.a", first)
	}
	second, ok := streams.next()
	if !ok || second != "aaa.b" {
		t.Fatalf("second domain = %q, want aa.b", second)
	}

	seen := map[string]bool{first: true, second: true}
	for {
		domain, ok := streams.next()
		if !ok {
			break
		}
		if seen[domain] {
			t.Fatalf("duplicate domain %q", domain)
		}
		seen[domain] = true
	}
	if len(seen) != 8 {
		t.Fatalf("got %d unique domains, want 8", len(seen))
	}
}

func TestLabelStreamPrefix(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	stream := newLabelStream(3, "ab", "aa", rng, true)
	got := collectLabels(stream)
	want := []string{"aaa", "aab"}
	if len(got) != len(want) {
		t.Fatalf("length 3: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("length 3 label %d: got %q, want %q", i, got[i], want[i])
		}
	}

	stream = newLabelStream(4, "ab", "aa", rng, true)
	got = collectLabels(stream)
	want = []string{"aaaa", "aaab", "aaba", "aabb"}
	if len(got) != len(want) {
		t.Fatalf("length 4: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("length 4 label %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestValidateSequentialPrefix(t *testing.T) {
	if err := validateSequentialPrefix("aa", []string{"fm"}, 5); err != nil {
		t.Errorf("two-letter prefix should fit a 3-char label: %v", err)
	}
	if err := validateSequentialPrefix("aaa", []string{"fm"}, 5); err == nil {
		t.Error("prefix equal to the label length should be rejected")
	}
	if err := validateSequentialPrefix("aa", []string{"com"}, 5); err == nil {
		t.Error("prefix equal to a 2-char label should be rejected")
	}
}
