package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

const (
	tldListAPIURL  = "https://api.tld-list.com/v1/extension/getCheapestRegistrar"
	tldListPageURL = "https://tld-list.com/tld/"
	priceWorkers   = 4

	priceSourceAPI  = "tld-list API"
	priceSourcePage = "tld-list page"

	priceBrowserUA = "Mozilla/5.0 (X11; Linux x86_64) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

type pricePageResult struct {
	tld   string
	price *Price
	err   error
}

type tldListOffer struct {
	Name          string `json:"name"`
	Price         string `json:"price"`
	PriceCurrency string `json:"priceCurrency"`
	OfferedBy     struct {
		Name string `json:"name"`
	} `json:"offeredBy"`
}

type tldListProduct struct {
	Type   string         `json:"@type"`
	Name   string         `json:"name"`
	Offers []tldListOffer `json:"offers"`
}

type tldListAPIEntry struct {
	Name     string `json:"name"`
	Currency string `json:"currency"`
	Cheapest struct {
		Register []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Price string `json:"price"`
		} `json:"register"`
		Renewal []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Price string `json:"price"`
		} `json:"renewal"`
	} `json:"cheapest"`
}

type tldListAPIResponse struct {
	Status string            `json:"status"`
	Data   []tldListAPIEntry `json:"data"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// EnrichPrices fetches cheapest registration/renewal prices for the available
// results. Cached prices are used first; missing prices come from the tld-list
// API when keys are configured, then from the public tld-list pages.
func (s *Scanner) EnrichPrices(ctx context.Context, emit *Emitter) (int, error) {
	results := s.Results()
	if len(results) == 0 {
		return 0, nil
	}

	tldSet := make(map[string]struct{})
	for _, result := range results {
		if tld := s.matchingTLD(result.Domain); tld != "" {
			tldSet[tld] = struct{}{}
		}
	}
	tlds := make([]string, 0, len(tldSet))
	for tld := range tldSet {
		tlds = append(tlds, tld)
	}
	sort.Strings(tlds)

	total := len(tlds)
	emit.Send(Event{
		Type:    EventPricing,
		Pricing: PricingProgress{Total: total},
	})
	done := 0
	prices := make(map[string]*Price)
	var missing []string

	for _, tld := range tlds {
		if price, ok := s.cache.GetPrice(tld); ok {
			prices[tld] = price
			done++
			emit.Send(Event{
				Type: EventPricing,
				Pricing: PricingProgress{
					Done: done, Total: total, TLD: tld,
					Price: price, Cached: true,
				},
			})
		} else {
			missing = append(missing, tld)
		}
	}

	var failures []error

	if len(missing) > 0 &&
		s.cfg.TLDListPublicKey != "" && s.cfg.TLDListPrivateKey != "" {
		fetched, err := s.fetchPricesAPI(ctx, missing)
		if err != nil {
			failures = append(failures, err)
			emit.Logf(LogWarn, "tld-list API: %v; trying public pages", err)
		}
		stillMissing := make([]string, 0, len(missing))
		for _, tld := range missing {
			if price, ok := fetched[tld]; ok {
				prices[tld] = price
				s.cache.PutPrice(tld, price)
				done++
				emit.Send(Event{
					Type: EventPricing,
					Pricing: PricingProgress{
						Done: done, Total: total, TLD: tld, Price: price,
					},
				})
			} else {
				stillMissing = append(stillMissing, tld)
			}
		}
		missing = stillMissing
	}

	if len(missing) > 0 {
		scraped, errs := s.fetchPricesPages(ctx, missing, total, done, emit)
		for tld, price := range scraped {
			prices[tld] = price
			s.cache.PutPrice(tld, price)
		}
		done += len(missing)
		failures = append(failures, errs...)
	}

	s.mu.Lock()
	priced := 0
	for i := range s.found {
		tld := s.matchingTLD(s.found[i].Domain)
		if price, ok := prices[tld]; ok {
			copied := *price
			s.found[i].Price = &copied
			priced++
		}
	}
	s.mu.Unlock()

	missingPrices := 0
	for _, tld := range tlds {
		if _, ok := prices[tld]; !ok {
			missingPrices++
		}
	}
	if missingPrices > 0 {
		if len(failures) > 0 {
			return priced, fmt.Errorf(
				"could not fetch prices for %d TLD(s): %w",
				missingPrices, errors.Join(failures...))
		}
		return priced, fmt.Errorf(
			"could not fetch prices for %d TLD(s)", missingPrices)
	}
	return priced, nil
}

func (s *Scanner) fetchPricesAPI(
	ctx context.Context,
	tlds []string,
) (map[string]*Price, error) {
	prices := make(map[string]*Price)
	var failures []error

	const chunkSize = 100
	for start := 0; start < len(tlds); start += chunkSize {
		end := start + chunkSize
		if end > len(tlds) {
			end = len(tlds)
		}
		payload, err := json.Marshal(map[string]any{
			"apiKeyPublic":  s.cfg.TLDListPublicKey,
			"apiKeyPrivate": s.cfg.TLDListPrivateKey,
			"extensions":    tlds[start:end],
			"pricetypes":    []string{"register", "renewal"},
		})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		body, status, err := s.priceRequest(ctx, http.MethodPost, tldListAPIURL, payload)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if status != http.StatusOK {
			failures = append(failures, fmt.Errorf("tld-list API HTTP %d", status))
			continue
		}
		parsed, err := parsePriceAPIResponse(body)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for tld, price := range parsed {
			prices[tld] = price
		}
	}
	if len(failures) > 0 {
		return prices, errors.Join(failures...)
	}
	return prices, nil
}

func parsePriceAPIResponse(body []byte) (map[string]*Price, error) {
	var response tldListAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("tld-list API response: %w", err)
	}
	if response.Status != "" && !strings.EqualFold(response.Status, "SUCCESS") {
		messages := make([]string, 0, len(response.Errors))
		for _, item := range response.Errors {
			messages = append(messages, item.Code+": "+item.Message)
		}
		if len(messages) == 0 {
			messages = append(messages, "status "+response.Status)
		}
		return nil, fmt.Errorf("tld-list API: %s", strings.Join(messages, "; "))
	}

	prices := make(map[string]*Price)
	for _, entry := range response.Data {
		tld := strings.ToLower(strings.TrimSpace(entry.Name))
		if tld == "" {
			continue
		}
		price := &Price{
			Currency: entry.Currency,
			Source:   priceSourceAPI,
		}
		if len(entry.Cheapest.Register) > 0 {
			price.Registration = parsePriceNumber(entry.Cheapest.Register[0].Price)
			price.RegistrationRegistrar = entry.Cheapest.Register[0].Name
		}
		if len(entry.Cheapest.Renewal) > 0 {
			price.Renewal = parsePriceNumber(entry.Cheapest.Renewal[0].Price)
			price.RenewalRegistrar = entry.Cheapest.Renewal[0].Name
		}
		if price.Currency == "" {
			price.Currency = "USD"
		}
		if price.Registration > 0 || price.Renewal > 0 {
			prices[tld] = price
		}
	}
	if len(prices) == 0 {
		return nil, fmt.Errorf("tld-list API returned no prices")
	}
	return prices, nil
}

func (s *Scanner) fetchPricesPages(
	ctx context.Context,
	tlds []string,
	total, alreadyDone int,
	emit *Emitter,
) (map[string]*Price, []error) {
	jobs := make(chan string)
	results := make(chan pricePageResult)
	var wg sync.WaitGroup

	workers := priceWorkers
	if workers > len(tlds) {
		workers = len(tlds)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tld := range jobs {
				price, err := s.fetchPricePage(ctx, tld)
				results <- pricePageResult{tld: tld, price: price, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, tld := range tlds {
			select {
			case jobs <- tld:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	prices := make(map[string]*Price)
	var failures []error
	done := alreadyDone
	for result := range results {
		done++
		if result.err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", result.tld, result.err))
			emit.Send(Event{
				Type: EventPricing,
				Pricing: PricingProgress{
					Done: done, Total: total, TLD: result.tld,
					Err: result.err.Error(),
				},
			})
			continue
		}
		prices[result.tld] = result.price
		emit.Send(Event{
			Type: EventPricing,
			Pricing: PricingProgress{
				Done: done, Total: total, TLD: result.tld, Price: result.price,
			},
		})
	}
	return prices, failures
}

func (s *Scanner) fetchPricePage(ctx context.Context, tld string) (*Price, error) {
	if curl, err := exec.LookPath("curl"); err == nil {
		price, curlErr := s.fetchPricePageCurl(ctx, curl, tld)
		if curlErr == nil {
			return price, nil
		}
		price, goErr := s.fetchPricePageGo(ctx, tld)
		if goErr == nil {
			return price, nil
		}
		return nil, fmt.Errorf("curl: %v; http: %w", curlErr, goErr)
	}
	return s.fetchPricePageGo(ctx, tld)
}

func (s *Scanner) fetchPricePageCurl(
	ctx context.Context,
	curl, tld string,
) (*Price, error) {
	target := tldListPageURL + url.PathEscape(tld)
	args := []string{
		"--silent", "--show-error", "--location", "--max-time", "20",
		"--http2",
		"-A", priceBrowserUA,
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9," +
			"image/avif,image/webp,*/*;q=0.8",
		"-H", "Accept-Language: en-US,en;q=0.9",
		"-H", "Sec-Fetch-Dest: document",
		"-H", "Sec-Fetch-Mode: navigate",
		"-H", "Sec-Fetch-Site: none",
		"-H", "Upgrade-Insecure-Requests: 1",
		"--write-out", "\n%{http_code}",
		target,
	}
	output, err := exec.CommandContext(ctx, curl, args...).Output()
	if err != nil {
		return nil, err
	}
	index := bytes.LastIndexByte(output, '\n')
	if index < 0 {
		return nil, fmt.Errorf("curl returned no status")
	}
	body := output[:index]
	status := strings.TrimSpace(string(output[index+1:]))
	if status != "200" {
		return nil, fmt.Errorf("HTTP %s", status)
	}
	if bytes.Contains(body, []byte("Just a moment")) ||
		bytes.Contains(body, []byte("cf-challenge")) {
		return nil, fmt.Errorf("Cloudflare challenge")
	}
	return parsePriceHTML(body)
}

func (s *Scanner) fetchPricePageGo(ctx context.Context, tld string) (*Price, error) {
	target := tldListPageURL + url.PathEscape(tld)
	body, status, err := s.priceRequest(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	if bytes.Contains(body, []byte("Just a moment")) ||
		bytes.Contains(body, []byte("cf-challenge")) {
		return nil, fmt.Errorf("Cloudflare challenge")
	}
	return parsePriceHTML(body)
}

func (s *Scanner) priceRequest(
	ctx context.Context,
	method, target string,
	payload []byte,
) ([]byte, int, error) {
	urls := s.proxy.sequence(target)
	if len(s.proxy.Templates()) > 0 {
		// tld-list rejects some hosted proxies with a Cloudflare challenge;
		// keep a direct request as the final fallback.
		urls = append(urls, target)
	}
	attempts := max(2, len(urls))
	var lastErr error
	lastStatus := 0

	for attempt := 0; attempt < attempts; attempt++ {
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		req, err := http.NewRequestWithContext(
			requestCtx, method, urls[attempt%len(urls)], body,
		)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", priceBrowserUA)
		req.Header.Set("Accept",
			"text/html,application/xhtml+xml,application/xml;q=0.9,"+
				"image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Origin", "https://tld-list.com")
			req.Header.Set("Referer", "https://tld-list.com/")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "same-site")
		}
		resp, err := s.priceClient.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		lastStatus = resp.StatusCode
		if resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return data, resp.StatusCode, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("price request failed")
	}
	return nil, lastStatus, lastErr
}

func parsePriceHTML(body []byte) (*Price, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var scripts []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "script" {
			isJSONLD := false
			for _, attr := range node.Attr {
				if strings.EqualFold(attr.Key, "type") &&
					strings.Contains(strings.ToLower(attr.Val), "ld+json") {
					isJSONLD = true
				}
			}
			if isJSONLD {
				var text strings.Builder
				for child := node.FirstChild; child != nil; child = child.NextSibling {
					if child.Type == html.TextNode {
						text.WriteString(child.Data)
					}
				}
				if text.Len() > 0 {
					scripts = append(scripts, text.String())
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	for _, script := range scripts {
		var value any
		if json.Unmarshal([]byte(script), &value) != nil {
			continue
		}
		if price := findProductPrice(value); price != nil {
			return price, nil
		}
	}
	return nil, fmt.Errorf("no tld-list price data found in page")
}

func findProductPrice(value any) *Price {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if price := findProductPrice(item); price != nil {
				return price
			}
		}
	case map[string]any:
		if isProductType(typed["@type"]) {
			if price := priceFromOffers(typed["offers"]); price != nil {
				return price
			}
		}
		for _, item := range typed {
			if price := findProductPrice(item); price != nil {
				return price
			}
		}
	}
	return nil
}

func isProductType(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.EqualFold(typed, "Product")
	case []any:
		for _, item := range typed {
			if isProductType(item) {
				return true
			}
		}
	}
	return false
}

func priceFromOffers(value any) *Price {
	var offers []any
	switch typed := value.(type) {
	case []any:
		offers = typed
	case map[string]any:
		offers = []any{typed}
	default:
		return nil
	}

	price := &Price{Source: priceSourcePage}
	for _, item := range offers {
		offer, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := offer["name"].(string)
		lowerName := strings.ToLower(name)
		amount := parsePriceNumber(fmt.Sprint(offer["price"]))
		currency, _ := offer["priceCurrency"].(string)
		registrar := ""
		if offeredBy, ok := offer["offeredBy"].(map[string]any); ok {
			registrar, _ = offeredBy["name"].(string)
		}

		switch {
		case strings.Contains(lowerName, "registration"):
			if price.Registration == 0 || (amount > 0 && amount < price.Registration) {
				price.Registration = amount
				price.RegistrationRegistrar = registrar
			}
		case strings.Contains(lowerName, "renewal"):
			if price.Renewal == 0 || (amount > 0 && amount < price.Renewal) {
				price.Renewal = amount
				price.RenewalRegistrar = registrar
			}
		}
		if currency != "" {
			price.Currency = currency
		}
	}
	if price.Currency == "" {
		price.Currency = "USD"
	}
	if price.Registration == 0 && price.Renewal == 0 {
		return nil
	}
	return price
}

func parsePriceNumber(value string) float64 {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "$")
	value = strings.ReplaceAll(value, ",", "")
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return number
}
