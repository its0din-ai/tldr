package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// SortByRenewal sorts results by cheapest renewal price, lowest first.
// Results without a known renewal price go last. Ties use registration price,
// then domain name.
func SortByRenewal(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		ri, iok := resultRenewal(results[i])
		rj, jok := resultRenewal(results[j])
		if iok != jok {
			return iok
		}
		if iok && ri != rj {
			return ri < rj
		}
		regi, regiOK := resultRegistration(results[i])
		regj, regjOK := resultRegistration(results[j])
		if regiOK != regjOK {
			return regiOK
		}
		if regiOK && regi != regj {
			return regi < regj
		}
		return results[i].Domain < results[j].Domain
	})
}

func resultRenewal(result Result) (float64, bool) {
	if result.Price == nil || result.Price.Renewal <= 0 {
		return 0, false
	}
	return result.Price.Renewal, true
}

func resultRegistration(result Result) (float64, bool) {
	if result.Price == nil || result.Price.Registration <= 0 {
		return 0, false
	}
	return result.Price.Registration, true
}

func writeOutputs(results []Result, jsonPath, csvPath string) error {
	if jsonPath != "" {
		file, err := os.Create(jsonPath)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		for _, result := range results {
			if err := encoder.Encode(result); err != nil {
				file.Close()
				return err
			}
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	if csvPath != "" {
		file, err := os.Create(csvPath)
		if err != nil {
			return err
		}
		writer := csv.NewWriter(file)
		if err := writer.Write([]string{
			"domain", "length", "status", "method", "detail", "cached",
			"registration", "renewal", "currency",
			"registration_registrar", "renewal_registrar", "price_source",
		}); err != nil {
			file.Close()
			return err
		}
		for _, result := range results {
			registration, renewal, currency := "", "", ""
			registrationRegistrar, renewalRegistrar, priceSource := "", "", ""
			if result.Price != nil {
				registration = fmt.Sprintf("%.2f", result.Price.Registration)
				renewal = fmt.Sprintf("%.2f", result.Price.Renewal)
				currency = result.Price.Currency
				registrationRegistrar = result.Price.RegistrationRegistrar
				renewalRegistrar = result.Price.RenewalRegistrar
				priceSource = result.Price.Source
			}
			if err := writer.Write([]string{
				result.Domain,
				fmt.Sprintf("%d", result.Length),
				result.Status,
				result.Method,
				result.Detail,
				fmt.Sprintf("%t", result.Cached),
				registration, renewal, currency,
				registrationRegistrar, renewalRegistrar, priceSource,
			}); err != nil {
				file.Close()
				return err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

// RenderSummary writes the final human-readable report. The TUI calls this
// after restoring the normal screen; plain mode calls it when the run ends.
func RenderSummary(w io.Writer, summary *Summary) {
	if summary == nil {
		return
	}
	if summary.Mode == "search" {
		renderSearchSummary(w, summary)
		return
	}
	if summary.Mode != "scan" {
		return
	}
	stats := summary.Stats
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Scanned %d candidates in %.1fs\n",
		stats.Checked, summary.Elapsed.Seconds())
	fmt.Fprintf(w, "  available: %d   taken: %d   unknown: %d   canceled: %d   cache hits: %d\n",
		stats.Available, stats.Taken, stats.Unknown, stats.Canceled, stats.CacheHits)
	fmt.Fprintf(w, "  queries: DNS %d, RDAP %d, WHOIS %d\n",
		stats.DNSQueries, stats.RDAPQueries, stats.WHOISQueries)
	if summary.StopReason != "" {
		fmt.Fprintf(w, "  stopped: %s\n", summary.StopReason)
	}
	if summary.Err != nil {
		fmt.Fprintf(w, "  error: %v\n", summary.Err)
	}

	if len(summary.Results) == 0 {
		fmt.Fprintln(w, "\nNo available domains found in the scanned range.")
		return
	}

	shortest := summary.Shortest
	shortestResults := make([]Result, 0, len(summary.Results))
	for _, result := range summary.Results {
		if result.Length == shortest {
			shortestResults = append(shortestResults, result)
		}
	}
	if summary.Plan.BestPrice {
		SortByRenewal(shortestResults)
	} else {
		sort.Slice(shortestResults, func(i, j int) bool {
			return shortestResults[i].Domain < shortestResults[j].Domain
		})
	}

	fmt.Fprintf(w, "\nShortest available domains (%d characters):\n", shortest)
	header := fmt.Sprintf("  %-22s%4s  %-6s", "DOMAIN", "LEN", "METHOD")
	if summary.Plan.BestPrice {
		header += fmt.Sprintf(" %9s %9s", "REG", "RENEW")
	}
	fmt.Fprintln(w, header)
	for _, result := range shortestResults {
		note := ""
		if result.Cached {
			note += " (cached)"
		}
		if result.Method == "dns" {
			note += " (unverified)"
		}
		line := fmt.Sprintf("  %-22s%4d  %-6s",
			result.Domain, result.Length, result.Method)
		if summary.Plan.BestPrice {
			reg, renewal := summaryPriceColumns(result.Price)
			line += fmt.Sprintf(" %9s %9s", reg, renewal)
		}
		fmt.Fprintln(w, line+note)
	}
	fmt.Fprintln(w, "\nReminder: unregistered != guaranteed registrable. Short labels "+
		"may be registry-reserved, premium, or restricted by local-presence rules.")
}

// FormatDuration is a small helper shared by the TUI and plain output.
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%02ds", minutes, seconds)
}

func renderSearchSummary(w io.Writer, summary *Summary) {
	stats := summary.Stats
	total := summary.SearchTotal
	if total == 0 {
		total = summary.Plan.SearchTotal
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Searched %s across %d TLDs in %.1fs\n",
		summary.SearchLabel, total, summary.Elapsed.Seconds())
	fmt.Fprintf(w, "  available: %d   taken: %d   unknown: %d   canceled: %d   cache hits: %d\n",
		stats.Available, stats.Taken, stats.Unknown, stats.Canceled, stats.CacheHits)
	fmt.Fprintf(w, "  queries: DNS %d, RDAP %d, WHOIS %d\n",
		stats.DNSQueries, stats.RDAPQueries, stats.WHOISQueries)
	if summary.StopReason != "" {
		fmt.Fprintf(w, "  stopped: %s\n", summary.StopReason)
	}
	if summary.Err != nil {
		fmt.Fprintf(w, "  error: %v\n", summary.Err)
	}
	if len(summary.Results) == 0 {
		fmt.Fprintln(w, "\nNo available domains found.")
		return
	}

	results := append([]Result(nil), summary.Results...)
	if summary.Plan.BestPrice {
		SortByRenewal(results)
	} else {
		sort.Slice(results, func(i, j int) bool {
			if results[i].Length != results[j].Length {
				return results[i].Length < results[j].Length
			}
			return results[i].Domain < results[j].Domain
		})
	}
	fmt.Fprintf(w, "\nAvailable domains for %s:\n", summary.SearchLabel)
	header := fmt.Sprintf("  %-22s%4s  %-6s", "DOMAIN", "LEN", "METHOD")
	if summary.Plan.BestPrice {
		header += fmt.Sprintf(" %9s %9s", "REG", "RENEW")
	}
	fmt.Fprintln(w, header)
	for _, result := range results {
		note := ""
		if result.Cached {
			note += " (cached)"
		}
		if result.Method == "dns" {
			note += " (unverified)"
		}
		line := fmt.Sprintf("  %-22s%4d  %-6s",
			result.Domain, result.Length, result.Method)
		if summary.Plan.BestPrice {
			reg, renewal := summaryPriceColumns(result.Price)
			line += fmt.Sprintf(" %9s %9s", reg, renewal)
		}
		fmt.Fprintln(w, line+note)
	}
	fmt.Fprintln(w, "\nReminder: unregistered != guaranteed registrable. Short labels "+
		"may be registry-reserved, premium, or restricted by local-presence rules.")
}

func summaryPriceColumns(price *Price) (string, string) {
	if price == nil {
		return "-", "-"
	}
	currency := price.Currency
	if currency == "" {
		currency = "USD"
	}
	format := func(value float64) string {
		if value <= 0 {
			return "-"
		}
		if strings.EqualFold(currency, "USD") {
			return fmt.Sprintf("$%.2f", value)
		}
		return fmt.Sprintf("%.2f %s", value, currency)
	}
	return format(price.Registration), format(price.Renewal)
}
