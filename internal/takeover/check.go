package takeover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/dnsresolve"
	"github.com/hidden-investigations/subflare/internal/model"
)

type fingerprint struct {
	Provider          string   `json:"Provider"`
	Suffixes          []string `json:"Suffixes"`
	Indicators        []string `json:"Indicators"`
	ExcludeIndicators []string `json:"ExcludeIndicators,omitempty"`
	StatusCodes       []int    `json:"StatusCodes,omitempty"`
}

type takeoverMatch struct {
	Provider   string
	Target     string
	Indicators []string
	Excludes   []string
	Statuses   []int
}

type hostTask struct {
	Index   int
	Host    string
	Matches []takeoverMatch
}

type cnameResolution struct {
	Resolved bool
	Dangling bool
	Reason   string
}

type httpSnapshot struct {
	Status int
	Text   string
}

func CheckResults(ctx context.Context, results []model.Result, resolver *dnsresolve.Resolver, timeout time.Duration, threads int) ([]model.Result, int, int) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if threads < 1 {
		threads = defaultWorkerCount(len(results))
	}
	if len(results) == 0 {
		return results, 0, 0
	}

	out := make([]model.Result, len(results))
	copy(out, results)

	tasks := make([]hostTask, 0, len(results))
	targetSet := map[string]struct{}{}
	for idx := range out {
		matches := buildMatches(out[idx].CNAMEs)
		if len(matches) == 0 {
			continue
		}
		tasks = append(tasks, hostTask{
			Index:   idx,
			Host:    out[idx].Host,
			Matches: matches,
		})
		for _, m := range matches {
			targetSet[m.Target] = struct{}{}
		}
	}
	if len(tasks) == 0 {
		return out, 0, 0
	}

	targetResolution := resolveCNAMETargets(ctx, resolver, targetSet, threads)
	checked := len(tasks)
	signals := 0

	bodyTasks := make([]hostTask, 0, len(tasks))
	for _, task := range tasks {
		flagged := false
		for _, match := range task.Matches {
			state := targetResolution[match.Target]
			if !state.Dangling {
				continue
			}
			reason := "dangling cname target"
			if state.Reason != "" {
				reason = fmt.Sprintf("dangling cname target (%s)", state.Reason)
			}
			markPotential(&out[task.Index], match.Provider, reason, "high")
			signals++
			flagged = true
			break
		}
		if flagged {
			continue
		}

		title := strings.ToLower(strings.TrimSpace(out[task.Index].HTTPTitle))
		status := out[task.Index].HTTPStatus
		if title != "" {
			for _, match := range task.Matches {
				if matchesHTTPFingerprint(match, status, title) {
					markPotential(&out[task.Index], match.Provider, "service fingerprint matched", confidenceFromHTTP(status, match))
					signals++
					flagged = true
					break
				}
			}
		}
		if flagged {
			continue
		}
		bodyTasks = append(bodyTasks, task)
	}

	if len(bodyTasks) == 0 {
		return out, checked, signals
	}

	client := &http.Client{Timeout: timeout}
	responseByHost := fetchResponses(ctx, client, bodyTasks, timeout, threads)
	for _, task := range bodyTasks {
		snapshot := responseByHost[task.Host]
		if snapshot.Status == 0 && snapshot.Text == "" {
			continue
		}
		baseTitle := strings.ToLower(strings.TrimSpace(out[task.Index].HTTPTitle))
		combinedText := strings.TrimSpace(baseTitle + "\n" + snapshot.Text)
		status := snapshot.Status
		if out[task.Index].HTTPStatus > 0 {
			status = out[task.Index].HTTPStatus
		}
		for _, match := range task.Matches {
			if matchesHTTPFingerprint(match, status, combinedText) {
				markPotential(&out[task.Index], match.Provider, "service fingerprint matched", confidenceFromHTTP(status, match))
				signals++
				break
			}
		}
	}

	return out, checked, signals
}

func matchFingerprint(cname string) (fingerprint, bool) {
	for _, fp := range fingerprintSnapshot() {
		for _, suffix := range fp.Suffixes {
			if strings.HasSuffix(cname, suffix) {
				return fp, true
			}
		}
	}
	return fingerprint{}, false
}

func buildMatches(cnames []string) []takeoverMatch {
	seen := map[string]struct{}{}
	out := make([]takeoverMatch, 0, len(cnames))
	for _, cname := range cnames {
		target := strings.TrimSpace(strings.ToLower(cname))
		if target == "" {
			continue
		}
		fp, ok := matchFingerprint(target)
		if !ok {
			continue
		}
		key := fp.Provider + "|" + target
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		indicators := make([]string, 0, len(fp.Indicators))
		for _, indicator := range fp.Indicators {
			indicator = strings.TrimSpace(strings.ToLower(indicator))
			if indicator != "" {
				indicators = append(indicators, indicator)
			}
		}
		excludes := make([]string, 0, len(fp.ExcludeIndicators))
		for _, indicator := range fp.ExcludeIndicators {
			indicator = strings.TrimSpace(strings.ToLower(indicator))
			if indicator != "" {
				excludes = append(excludes, indicator)
			}
		}
		statuses := uniqueStatusCodes(fp.StatusCodes)
		out = append(out, takeoverMatch{
			Provider:   fp.Provider,
			Target:     target,
			Indicators: indicators,
			Excludes:   excludes,
			Statuses:   statuses,
		})
	}
	return out
}

func resolveCNAMETargets(ctx context.Context, resolver *dnsresolve.Resolver, targetSet map[string]struct{}, threads int) map[string]cnameResolution {
	out := make(map[string]cnameResolution, len(targetSet))
	if len(targetSet) == 0 {
		return out
	}
	targets := make([]string, 0, len(targetSet))
	for target := range targetSet {
		targets = append(targets, target)
	}

	if resolver == nil {
		for _, target := range targets {
			out[target] = cnameResolution{Resolved: true}
		}
		return out
	}

	if threads < 1 {
		threads = 1
	}
	if threads > len(targets) {
		threads = len(targets)
	}

	type resolveResult struct {
		Target string
		State  cnameResolution
	}
	jobs := make(chan string)
	results := make(chan resolveResult, len(targets))
	wg := sync.WaitGroup{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				ips, cnames, err := resolver.QueryA(ctx, target)
				if err == nil && (len(ips) > 0 || len(cnames) > 0) {
					results <- resolveResult{
						Target: target,
						State:  cnameResolution{Resolved: true},
					}
					continue
				}
				dangling, reason := classifyDNSError(err)
				results <- resolveResult{
					Target: target,
					State: cnameResolution{
						Resolved: false,
						Dangling: dangling,
						Reason:   reason,
					},
				}
			}
		}()
	}

	go func() {
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for result := range results {
		out[result.Target] = result.State
	}

	return out
}

func fetchResponses(ctx context.Context, client *http.Client, tasks []hostTask, timeout time.Duration, threads int) map[string]httpSnapshot {
	hostSet := map[string]struct{}{}
	for _, task := range tasks {
		host := strings.TrimSpace(strings.ToLower(task.Host))
		if host == "" {
			continue
		}
		hostSet[host] = struct{}{}
	}
	if len(hostSet) == 0 {
		return nil
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	if threads < 1 {
		threads = 1
	}
	if threads > len(hosts) {
		threads = len(hosts)
	}

	jobs := make(chan string)
	wg := sync.WaitGroup{}
	out := make(map[string]httpSnapshot, len(hosts))
	mu := sync.Mutex{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				snapshot := fetchResponse(ctx, client, host, timeout)
				if snapshot.Status == 0 && snapshot.Text == "" {
					continue
				}
				mu.Lock()
				out[host] = snapshot
				mu.Unlock()
			}
		}()
	}

	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)
	wg.Wait()

	return out
}

func fetchResponse(ctx context.Context, client *http.Client, host string, timeout time.Duration) httpSnapshot {
	for _, scheme := range []string{"https://", "http://"} {
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, scheme+host, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Subflare/1.0")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		cancel()
		return httpSnapshot{
			Status: resp.StatusCode,
			Text:   strings.ToLower(string(body)),
		}
	}
	return httpSnapshot{}
}

func containsAny(text string, indicators []string) bool {
	if text == "" {
		return false
	}
	for _, indicator := range indicators {
		if indicator != "" && strings.Contains(text, indicator) {
			return true
		}
	}
	return false
}

func matchesHTTPFingerprint(match takeoverMatch, status int, text string) bool {
	if len(match.Indicators) == 0 || strings.TrimSpace(text) == "" {
		return false
	}
	if len(match.Statuses) > 0 && status > 0 && !statusAllowed(status, match.Statuses) {
		return false
	}
	if containsAny(text, match.Excludes) {
		return false
	}
	return containsAny(text, match.Indicators)
}

func statusAllowed(status int, allowed []int) bool {
	if status < 1 || len(allowed) == 0 {
		return true
	}
	for _, value := range allowed {
		if status == value {
			return true
		}
	}
	return false
}

func uniqueStatusCodes(values []int) []int {
	set := map[int]struct{}{}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value < 100 || value > 599 {
			continue
		}
		if _, exists := set[value]; exists {
			continue
		}
		set[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func classifyDNSError(err error) (bool, string) {
	if err == nil {
		return false, ""
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case message == "":
		return false, ""
	case strings.Contains(message, "nxdomain"):
		return true, "nxdomain"
	case strings.Contains(message, "no such host"):
		return true, "no such host"
	case strings.Contains(message, "name error"):
		return true, "name error"
	default:
		return false, ""
	}
}

func markPotential(result *model.Result, provider, reason, confidence string) {
	if strings.TrimSpace(confidence) == "" {
		confidence = "low"
	}
	if !result.TakeoverPotential {
		result.TakeoverPotential = true
		result.TakeoverProvider = provider
		result.TakeoverReason = reason
		result.TakeoverConfidence = confidence
		return
	}
	if confidenceRank(confidence) > confidenceRank(result.TakeoverConfidence) {
		result.TakeoverProvider = provider
		result.TakeoverReason = reason
		result.TakeoverConfidence = confidence
	}
}

func confidenceFromHTTP(status int, match takeoverMatch) string {
	if status > 0 && statusAllowed(status, match.Statuses) {
		return "medium"
	}
	if len(match.Statuses) == 0 {
		return "medium"
	}
	return "low"
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func defaultWorkerCount(total int) int {
	if total <= 0 {
		return 1
	}
	workers := runtime.GOMAXPROCS(0) * 4
	if workers < 8 {
		workers = 8
	}
	if workers > 64 {
		workers = 64
	}
	if workers > total {
		workers = total
	}
	return workers
}
