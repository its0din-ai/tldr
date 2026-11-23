package scanner

import (
	"reflect"
	"testing"
)

func TestSelectTLDsForSearch(t *testing.T) {
	all := []string{"ac", "com", "net", "info", "co.uk", "io"}

	tlds, err := selectTLDs(all, &Config{Search: "gnu", MaxTLDLen: 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ac", "io"}; !reflect.DeepEqual(tlds, want) {
		t.Errorf("max 2: got %v, want %v", tlds, want)
	}

	tlds, err = selectTLDs(all, &Config{Search: "gnu", MaxTLDLen: 3})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ac", "com", "net", "io"}; !reflect.DeepEqual(tlds, want) {
		t.Errorf("max 3: got %v, want %v", tlds, want)
	}

	tlds, err = selectTLDs(all, &Config{
		Search: "gnu", MaxTLDLen: 2, TLDsRaw: "com,net",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"com", "net"}; !reflect.DeepEqual(tlds, want) {
		t.Errorf("explicit: got %v, want %v", tlds, want)
	}

	tlds, err = selectTLDs(all, &Config{
		Search: "gnu", MaxTLDLen: 3, ExcludeRaw: "net,io",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ac", "com"}; !reflect.DeepEqual(tlds, want) {
		t.Errorf("exclude: got %v, want %v", tlds, want)
	}
}
