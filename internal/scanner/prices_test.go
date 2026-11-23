package scanner

import (
	"path/filepath"
	"testing"
	"time"
)

const priceHTMLFixture = `<!doctype html>
<html><head>
<script type="application/ld+json">[
  {"@context":"https://schema.org","@type":"Product","name":".com domain",
   "offers":[
    {"@type":"Offer","name":".com domain registration","price":"3.80",
     "priceCurrency":"USD","offeredBy":{"@type":"Organization","name":"Spaceship"}},
    {"@type":"Offer","name":".com domain renewal","price":"10.15",
     "priceCurrency":"USD","offeredBy":{"@type":"Organization","name":"Sav"}},
    {"@type":"Offer","name":".com domain transfer","price":"3.94",
     "priceCurrency":"USD","offeredBy":{"@type":"Organization","name":"Spaceship"}}
   ]}
]</script>
</head><body></body></html>`

func TestParsePriceHTML(t *testing.T) {
	price, err := parsePriceHTML([]byte(priceHTMLFixture))
	if err != nil {
		t.Fatal(err)
	}
	if price.Registration != 3.80 || price.Renewal != 10.15 {
		t.Errorf("prices = %v/%v, want 3.80/10.15",
			price.Registration, price.Renewal)
	}
	if price.Currency != "USD" {
		t.Errorf("currency = %q, want USD", price.Currency)
	}
	if price.RegistrationRegistrar != "Spaceship" ||
		price.RenewalRegistrar != "Sav" {
		t.Errorf("registrars = %q/%q, want Spaceship/Sav",
			price.RegistrationRegistrar, price.RenewalRegistrar)
	}
}

func TestParsePriceAPIResponse(t *testing.T) {
	body := []byte(`{
	  "status":"SUCCESS",
	  "data":[{
	    "name":"com","currency":"USD",
	    "cheapest":{
	      "register":[{"id":"spaceship","name":"Spaceship","price":"3.80"}],
	      "renewal":[{"id":"sav","name":"Sav","price":"10.15"}]
	    }
	  }],
	  "errors":[]
	}`)
	prices, err := parsePriceAPIResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	price := prices["com"]
	if price == nil {
		t.Fatal("missing .com price")
	}
	if price.Registration != 3.80 || price.Renewal != 10.15 {
		t.Errorf("prices = %v/%v, want 3.80/10.15",
			price.Registration, price.Renewal)
	}
	if price.Source != priceSourceAPI {
		t.Errorf("source = %q, want %q", price.Source, priceSourceAPI)
	}
}

func TestParsePriceAPIResponseError(t *testing.T) {
	body := []byte(`{"status":"FAIL","errors":[{"code":"AUTH_INVALID","message":"bad keys"}]}`)
	if _, err := parsePriceAPIResponse(body); err == nil {
		t.Fatal("expected an API error")
	}
}

func TestCachePrices(t *testing.T) {
	cache, err := NewCache(
		filepath.Join(t.TempDir(), "cache.db"), 7*24*time.Hour, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	cache.PutPrice("com", &Price{
		Registration: 3.80, Renewal: 10.15, Currency: "USD",
		RegistrationRegistrar: "Spaceship", RenewalRegistrar: "Sav",
		Source: priceSourceAPI,
	})
	price, ok := cache.GetPrice("com")
	if !ok {
		t.Fatal("expected cached price")
	}
	if price.Registration != 3.80 || price.Renewal != 10.15 {
		t.Fatalf("unexpected price: %+v", price)
	}

	if _, err := cache.db.Exec(
		"UPDATE prices SET checked_at = ? WHERE tld = ?",
		time.Now().Add(-25*time.Hour).Unix(), "com",
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.GetPrice("com"); ok {
		t.Fatal("expected expired price to be ignored")
	}
}

func TestSortByRenewal(t *testing.T) {
	results := []Result{
		{Domain: "b.fm", Price: &Price{Renewal: 10, Registration: 4}},
		{Domain: "a.fm", Price: &Price{Renewal: 5, Registration: 3}},
		{Domain: "c.fm"},
		{Domain: "d.fm", Price: &Price{Renewal: 5, Registration: 2}},
	}
	SortByRenewal(results)
	want := []string{"d.fm", "a.fm", "b.fm", "c.fm"}
	for i := range want {
		if results[i].Domain != want[i] {
			t.Fatalf("order = %v, want %v",
				[]string{results[0].Domain, results[1].Domain, results[2].Domain, results[3].Domain},
				want)
		}
	}
}
