package infra

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
	"github.com/miekg/dns"
)

type asnInfo struct {
	ASN string
	Org string
}

var cdnCNAMEHints = []struct {
	Suffix   string
	Provider string
}{
	{Suffix: ".cloudfront.net", Provider: "cloudfront"},
	{Suffix: ".cloudflare.net", Provider: "cloudflare"},
	{Suffix: ".cdn.cloudflare.net", Provider: "cloudflare"},
	{Suffix: ".fastly.net", Provider: "fastly"},
	{Suffix: ".edgesuite.net", Provider: "akamai"},
	{Suffix: ".akamaiedge.net", Provider: "akamai"},
	{Suffix: ".edgekey.net", Provider: "akamai"},
	{Suffix: ".vercel-dns.com", Provider: "vercel"},
	{Suffix: ".cdn.vercel.net", Provider: "vercel"},
	{Suffix: ".trafficmanager.net", Provider: "azure-frontdoor"},
	{Suffix: ".azureedge.net", Provider: "azure-cdn"},
	{Suffix: ".cdn77.org", Provider: "cdn77"},
	{Suffix: ".b-cdn.net", Provider: "bunny"},
	{Suffix: ".global.fastly.net", Provider: "fastly"},
}

var asnCDNMap = map[string]string{
	"AS13335": "cloudflare",
	"AS54113": "fastly",
	"AS20940": "akamai",
	"AS16509": "aws",
	"AS14618": "aws",
	"AS15169": "google",
	"AS8075":  "azure",
	"AS32934": "meta",
}

func EnrichResults(ctx context.Context, results []model.Result, resolvers []string, timeout time.Duration, threads int) ([]model.Result, int) {
	if len(results) == 0 {
		return results, 0
	}
	if threads < 1 {
		threads = 1
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	resolverList := normalizeResolvers(resolvers)
	if len(resolverList) == 0 {
		resolverList = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}

	out := make([]model.Result, len(results))
	jobs := make(chan int)
	wg := sync.WaitGroup{}
	asnCache := map[string]asnInfo{}
	cacheMu := sync.Mutex{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				item := results[idx]
				cdn := detectCDN(item)
				asns := make([]string, 0, len(item.IPs))
				orgHints := make([]string, 0, 1)

				for _, ip := range item.IPs {
					ip = strings.TrimSpace(ip)
					if ip == "" || strings.Contains(ip, ":") {
						continue
					}
					cacheMu.Lock()
					cached, ok := asnCache[ip]
					cacheMu.Unlock()
					if !ok {
						info, err := lookupASN(ctx, resolverList, ip, timeout)
						if err == nil {
							cached = info
						}
						cacheMu.Lock()
						asnCache[ip] = cached
						cacheMu.Unlock()
					}
					if cached.ASN != "" {
						asns = append(asns, cached.ASN)
					}
					if cached.Org != "" {
						orgHints = append(orgHints, cached.Org)
					}
				}

				asns = util.UniqueSorted(asns)
				orgHints = util.UniqueSorted(orgHints)

				if len(asns) > 0 {
					item.InfraASN = strings.Join(asns, ",")
					if cdn == "" {
						for _, asn := range asns {
							if provider, ok := asnCDNMap[asn]; ok {
								cdn = provider
								break
							}
						}
					}
				}
				if len(orgHints) > 0 {
					item.InfraOrg = orgHints[0]
				}
				if cdn != "" {
					item.InfraCDN = cdn
				}
				out[idx] = item
			}
		}()
	}

	for idx := range results {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()

	enriched := 0
	for i := range out {
		if out[i].InfraASN != "" || out[i].InfraCDN != "" || out[i].InfraOrg != "" {
			enriched++
		}
	}
	return out, enriched
}

func detectCDN(item model.Result) string {
	for _, cname := range item.CNAMEs {
		name := strings.ToLower(strings.TrimSpace(cname))
		for _, hint := range cdnCNAMEHints {
			if strings.HasSuffix(name, hint.Suffix) {
				return hint.Provider
			}
		}
	}
	combined := strings.ToLower(strings.Join(item.HTTPTech, "\n") + "\n" + item.HTTPTitle)
	if strings.Contains(combined, "cloudflare") {
		return "cloudflare"
	}
	if strings.Contains(combined, "akamai") {
		return "akamai"
	}
	if strings.Contains(combined, "fastly") {
		return "fastly"
	}
	if strings.Contains(combined, "cloudfront") {
		return "cloudfront"
	}
	if strings.Contains(combined, "vercel") {
		return "vercel"
	}
	return ""
}

func lookupASN(ctx context.Context, resolvers []string, ip string, timeout time.Duration) (asnInfo, error) {
	reversed, err := toCymruQueryName(ip)
	if err != nil {
		return asnInfo{}, err
	}
	question := dns.Fqdn(reversed + ".origin.asn.cymru.com")

	var lastErr error
	for _, resolver := range resolvers {
		req := new(dns.Msg)
		req.SetQuestion(question, dns.TypeTXT)

		client := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, qErr := client.ExchangeContext(ctx, req, resolver)
		if qErr != nil {
			lastErr = qErr
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("empty dns response")
			continue
		}
		if resp.Truncated {
			client = &dns.Client{Net: "tcp", Timeout: timeout}
			resp, _, qErr = client.ExchangeContext(ctx, req, resolver)
			if qErr != nil {
				lastErr = qErr
				continue
			}
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("dns rcode=%s", dns.RcodeToString[resp.Rcode])
			continue
		}
		for _, answer := range resp.Answer {
			txt, ok := answer.(*dns.TXT)
			if !ok || len(txt.Txt) == 0 {
				continue
			}
			parsed := parseCymruTXT(strings.Join(txt.Txt, " "))
			if parsed.ASN != "" {
				return parsed, nil
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("asn not found")
	}
	return asnInfo{}, lastErr
}

func parseCymruTXT(raw string) asnInfo {
	parts := strings.Split(raw, "|")
	if len(parts) < 1 {
		return asnInfo{}
	}
	trimmed := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed = append(trimmed, strings.TrimSpace(part))
	}
	asn := ""
	if len(trimmed) > 0 && trimmed[0] != "" {
		asn = trimmed[0]
		if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
			asn = "AS" + asn
		}
		asn = strings.ToUpper(asn)
	}
	org := ""
	if len(trimmed) >= 6 {
		org = trimmed[5]
	}
	return asnInfo{ASN: asn, Org: org}
}

func normalizeResolvers(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if !strings.Contains(value, ":") {
			value += ":53"
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func toCymruQueryName(ip string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", fmt.Errorf("invalid ip: %s", ip)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "", fmt.Errorf("ipv6 unsupported for cymru query")
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0]), nil
}
