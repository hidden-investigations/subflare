package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hidden-investigations/subflare/internal/bench"
	"github.com/hidden-investigations/subflare/internal/dnsresolve"
	"github.com/hidden-investigations/subflare/internal/httpprobe"
	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/options"
	"github.com/hidden-investigations/subflare/internal/output"
	"github.com/hidden-investigations/subflare/internal/pipeline"
	"github.com/hidden-investigations/subflare/internal/source"
	"github.com/hidden-investigations/subflare/internal/takeover"
	"github.com/hidden-investigations/subflare/internal/util"
	"github.com/hidden-investigations/subflare/internal/workflow"
)

const banner = `███████╗██╗   ██╗██████╗ ███████╗██╗      █████╗ ██████╗ ███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██║     ██╔══██╗██╔══██╗██╔════╝
███████╗██║   ██║██████╔╝█████╗  ██║     ███████║██████╔╝█████╗  
╚════██║██║   ██║██╔══██╗██╔══╝  ██║     ██╔══██║██╔══██╗██╔══╝  
███████║╚██████╔╝██████╔╝██║     ███████╗██║  ██║██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

        @sakibulalikhan
    Hiddeninvestigations.Net`

func main() {
	args := os.Args[1:]
	subcommand, args := parseSubcommand(args)

	if !options.RawNoBanner(args) && !options.RawStrictIO(args) {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, banner)
		fmt.Fprintln(os.Stderr)
	}

	if subcommand == "diff" {
		if err := runDiffCommand(stripGlobalFlags(args)); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
			os.Exit(1)
		}
		return
	}

	fs := flag.NewFlagSet("subflare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	opts, err := options.Parse(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			options.PrintHelp(os.Stdout, source.AvailableSourceNames())
			return
		}
		fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		fmt.Fprintln(os.Stderr, "Run `subflare --help` for usage.")
		os.Exit(1)
	}

	if opts.StrictIO {
		opts.Silent = true
		opts.NoBanner = true
	}

	if opts.ListSources {
		printSources(source.AvailableSourceNames())
		return
	}
	if opts.Takeover && subcommand != "scan" {
		fmt.Fprintln(os.Stderr, "[ERR] --takeover can only be used with the default scan command")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch subcommand {
	case "bench":
		result, benchErr := bench.Run(ctx, opts)
		if benchErr != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %v\n", benchErr)
			os.Exit(1)
		}
		fmt.Println(bench.Render(result))
	case "monitor":
		if err := runMonitor(ctx, opts); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
			os.Exit(1)
		}
	default:
		var runErr error
		if opts.Takeover {
			runErr = runTakeover(ctx, opts)
		} else {
			runErr = runScan(ctx, opts)
		}
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %v\n", runErr)
			os.Exit(1)
		}
	}
}

func runScan(ctx context.Context, opts options.Options) error {
	domains, err := collectDomains(opts)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("no valid domains provided")
	}

	allResults := []model.Result{}
	multiDomain := len(domains) > 1

	for idx, domain := range domains {
		runOpts := opts
		runOpts.Domain = domain
		startedAt := time.Now()

		report, runErr := pipeline.Run(ctx, runOpts)
		if runErr != nil {
			return fmt.Errorf("domain %s: %w", domain, runErr)
		}

		if !opts.Silent {
			if multiDomain {
				if idx > 0 {
					fmt.Fprintln(os.Stderr)
				}
				fmt.Fprintf(os.Stderr, "[INF] target domain: %s\n", domain)
			}
			printScanSummary(domain, report.Stats, time.Since(startedAt), opts.Verbose)
			printResultSection(len(report.Results))
		}

		if !opts.Silent && idx > 0 && len(report.Results) > 0 {
			fmt.Println()
		}

		for _, result := range report.Results {
			if opts.Silent {
				fmt.Println(result.Host)
			} else {
				fmt.Println(result.Host)
			}
			allResults = append(allResults, result)
		}

		if opts.TakeoverCheck && !opts.Silent {
			printTakeoverAssessment(report.Results)
		}
	}

	if opts.Output != "" {
		if err := output.WriteText(opts.Output, allResults); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[INF] wrote text output to %s\n", opts.Output)
		}
	}

	if opts.JSONL != "" {
		if err := output.WriteJSONL(opts.JSONL, allResults); err != nil {
			return fmt.Errorf("write jsonl: %w", err)
		}
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[INF] wrote JSONL output to %s\n", opts.JSONL)
		}
	}

	return nil
}

func runTakeover(ctx context.Context, opts options.Options) error {
	hosts, err := collectTakeoverHosts(opts)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return fmt.Errorf("takeover mode requires targets from -l, --stdin, pipe, or -d")
	}

	startedAt := time.Now()
	now := time.Now().UTC().Unix()
	candidates := make([]model.Candidate, 0, len(hosts))
	for _, host := range hosts {
		candidates = append(candidates, model.Candidate{
			Host:          host,
			Sources:       map[string]struct{}{"input": {}},
			FirstSeenUnix: now,
		})
	}

	resolver := dnsresolve.New(opts.Resolvers, opts.Timeout, opts.Retries)
	resolved, unresolved, resolveErr := dnsresolve.ResolveCandidatesWithBackend(ctx, candidates, resolver, dnsresolve.BackendConfig{
		Backend:     opts.DNSBackend,
		Threads:     opts.Threads,
		MassDNSPath: opts.MassDNSPath,
	})
	if resolveErr != nil {
		return fmt.Errorf("resolve input hosts: %w", resolveErr)
	}

	trustedResolver := dnsresolve.New(opts.TrustedResolvers, opts.Timeout, opts.Retries)
	validated, dropped := dnsresolve.ValidateResults(ctx, resolved, trustedResolver, opts.Threads)

	httpProbed := 0
	if opts.HTTPProbe {
		validated, httpProbed = httpprobe.ProbeResults(ctx, validated, opts.HTTPProbeThreads, opts.HTTPProbeTimeout)
	}

	checked, takeoverChecked, takeoverSignals := takeover.CheckResults(ctx, validated, trustedResolver, opts.TakeoverTimeout, opts.TakeoverThreads)
	flagged := filterTakeoverResults(checked)

	if opts.Silent {
		for _, result := range flagged {
			fmt.Println(result.Host)
		}
	} else {
		printTakeoverOnlySummary(takeoverOnlySummary{
			Elapsed:         time.Since(startedAt),
			InputHosts:      len(hosts),
			ResolvedHosts:   len(resolved),
			UnresolvedHosts: unresolved,
			TrustedDropped:  dropped,
			HTTPProbed:      httpProbed,
			TakeoverChecked: takeoverChecked,
			TakeoverSignals: takeoverSignals,
		}, opts.HTTPProbe)
		printTakeoverAssessment(checked)
	}

	if opts.Output != "" {
		if err := output.WriteText(opts.Output, flagged); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[INF] wrote text output to %s\n", opts.Output)
		}
	}
	if opts.JSONL != "" {
		if err := output.WriteJSONL(opts.JSONL, flagged); err != nil {
			return fmt.Errorf("write jsonl: %w", err)
		}
		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[INF] wrote JSONL output to %s\n", opts.JSONL)
		}
	}

	return nil
}

func runMonitor(ctx context.Context, opts options.Options) error {
	if opts.Domain == "" {
		return fmt.Errorf("monitor requires -d domain")
	}
	if opts.Stdin {
		return fmt.Errorf("monitor does not support --stdin")
	}

	interval := opts.MonitorInterval
	if interval <= 0 {
		interval = 10 * time.Minute
	}

	cycle := 0
	for {
		cycle++

		report, err := pipeline.Run(ctx, opts)
		if err != nil {
			return err
		}
		newHosts := workflow.HostsFromResults(report.Results)
		oldHosts, hasOld, loadErr := workflow.LoadSnapshot(opts.StateDir, opts.Domain)
		if loadErr != nil {
			return loadErr
		}
		delta := workflow.ComputeDiff(oldHosts, newHosts)

		if !opts.Silent {
			fmt.Fprintf(os.Stderr, "[MON] cycle=%d domain=%s total=%d new=%d removed=%d stable=%d\n", cycle, opts.Domain, len(newHosts), len(delta.New), len(delta.Removed), len(delta.Stable))
			if !hasOld {
				fmt.Fprintln(os.Stderr, "[MON] first run: baseline created")
			}
		}

		if opts.StrictIO {
			for _, host := range delta.New {
				fmt.Println(host)
			}
		}

		if len(delta.New) > 0 {
			errs := workflow.Dispatch(ctx, workflow.WebhookConfig{
				URLs:             opts.WebhookURLs,
				DiscordURL:       opts.DiscordWebhook,
				SlackURL:         opts.SlackWebhook,
				TelegramBotToken: opts.TelegramBotToken,
				TelegramChatID:   opts.TelegramChatID,
				Timeout:          opts.WebhookTimeout,
			}, opts.Domain, delta)
			if opts.Verbose {
				for _, webhookErr := range errs {
					fmt.Fprintf(os.Stderr, "[WARN] %v\n", webhookErr)
				}
			}
		}

		if saveErr := workflow.SaveSnapshot(opts.StateDir, opts.Domain, newHosts); saveErr != nil {
			return saveErr
		}

		if opts.MonitorCycles > 0 && cycle >= opts.MonitorCycles {
			return nil
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runDiffCommand(args []string) error {
	fs := flag.NewFlagSet("subflare diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	oldPath := ""
	newPath := ""
	show := "summary"
	jsonOut := false

	fs.Usage = func() {
		fmt.Println("Usage: subflare diff --old old.txt --new new.txt [--show summary|new|added|removed|deleted|stable|all] [--json]")
	}

	fs.StringVar(&oldPath, "old", "", "old result file (txt or jsonl)")
	fs.StringVar(&newPath, "new", "", "new result file (txt or jsonl)")
	fs.StringVar(&show, "show", "summary", "summary|new|added|removed|deleted|stable|all")
	fs.BoolVar(&jsonOut, "json", false, "print diff as JSON")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if oldPath == "" || newPath == "" {
		return fmt.Errorf("diff requires --old and --new")
	}

	oldHosts, err := workflow.ReadHostsFile(oldPath)
	if err != nil {
		return fmt.Errorf("read old file: %w", err)
	}
	newHosts, err := workflow.ReadHostsFile(newPath)
	if err != nil {
		return fmt.Errorf("read new file: %w", err)
	}

	delta := workflow.ComputeDiff(oldHosts, newHosts)
	if jsonOut {
		fmt.Printf("{\"new\":%d,\"removed\":%d,\"stable\":%d}\n", len(delta.New), len(delta.Removed), len(delta.Stable))
		return nil
	}

	switch normalizeDiffShowMode(show) {
	case "summary":
		fmt.Printf("new=%d removed=%d stable=%d\n", len(delta.New), len(delta.Removed), len(delta.Stable))
	case "new":
		printList(delta.New)
	case "removed":
		printList(delta.Removed)
	case "stable":
		printList(delta.Stable)
	case "all":
		fmt.Printf("[DIFF] new=%d removed=%d stable=%d\n", len(delta.New), len(delta.Removed), len(delta.Stable))
		fmt.Println("[DIFF] new:")
		printList(delta.New)
		fmt.Println("[DIFF] removed:")
		printList(delta.Removed)
		fmt.Println("[DIFF] stable:")
		printList(delta.Stable)
	default:
		return fmt.Errorf("unknown --show value: %s", show)
	}
	return nil
}

func normalizeDiffShowMode(show string) string {
	value := strings.ToLower(strings.TrimSpace(show))
	switch value {
	case "added":
		return "new"
	case "deleted":
		return "removed"
	default:
		return value
	}
}

func collectDomains(opts options.Options) ([]string, error) {
	return collectTargets(opts.Domain, opts.InputList, opts.Stdin, normalizeDomainInput)
}

func collectTakeoverHosts(opts options.Options) ([]string, error) {
	readStdin := opts.Stdin || stdinHasPipedData()
	return collectTargets(opts.Domain, opts.InputList, readStdin, normalizeHostInput)
}

func collectTargets(seed, listPath string, readStdin bool, normalize func(string) string) ([]string, error) {
	set := map[string]struct{}{}
	out := []string{}
	appendTarget := func(raw string) {
		target := normalize(raw)
		if target == "" {
			return
		}
		if _, exists := set[target]; exists {
			return
		}
		set[target] = struct{}{}
		out = append(out, target)
	}

	appendTarget(seed)
	if listPath != "" {
		file, err := os.Open(listPath)
		if err != nil {
			return nil, fmt.Errorf("read list file: %w", err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			appendTarget(line)
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("read list file: %w", err)
		}
		file.Close()
	}

	if readStdin {
		stdinPiped := stdinHasPipedData()
		shouldReadStdin := stdinPiped || len(out) == 0
		if !shouldReadStdin {
			sort.Strings(out)
			return out, nil
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			appendTarget(line)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	sort.Strings(out)
	return out, nil
}

func normalizeDomainInput(input string) string {
	return util.NormalizeDomain(util.NormalizeHost(input))
}

func normalizeHostInput(input string) string {
	host := util.NormalizeHost(input)
	if !strings.Contains(host, ".") {
		return ""
	}
	return host
}

func stdinHasPipedData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice == 0
}

func parseSubcommand(args []string) (string, []string) {
	if len(args) == 0 {
		return "scan", args
	}
	name := strings.ToLower(strings.TrimSpace(args[0]))
	switch name {
	case "bench", "diff", "monitor":
		return name, args[1:]
	default:
		return "scan", args
	}
}

func stripGlobalFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		normalized := strings.TrimSpace(strings.ToLower(arg))
		if normalized == "--no-banner" || normalized == "-no-banner" || strings.HasPrefix(normalized, "--no-banner=") || strings.HasPrefix(normalized, "-no-banner=") {
			continue
		}
		if normalized == "--strict-io" || normalized == "-strict-io" || strings.HasPrefix(normalized, "--strict-io=") || strings.HasPrefix(normalized, "-strict-io=") {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func printScanSummary(domain string, stats pipeline.Stats, duration time.Duration, verbose bool) {
	printInfoSection("scan summary")
	printInfoKV("domain", domain)
	printInfoKV("elapsed", formatDuration(duration))
	if stats.DNSBackend != "" {
		printInfoKV("dns backend", stats.DNSBackend)
	}
	if stats.PassiveSources > 0 {
		printInfoKV("passive sources", fmt.Sprintf("total=%d, succeeded=%d, failed=%d, cache_hits=%d", stats.PassiveSources, stats.PassiveSucceeded, stats.PassiveFailed, stats.PassiveCacheHits))
		printInfoKV("sources with findings", fmt.Sprintf("%d", countPositiveSources(stats.SourceCounts)))
		printTopSourceYields(stats.SourceCounts, stats.SourceCacheHits, 8)
	}
	printInfoKV("bruteforce seeded", fmt.Sprintf("%d", stats.BruteforceSeeded))
	if stats.PermutationSeeded > 0 {
		printInfoKV("permutation seeded", fmt.Sprintf("%d", stats.PermutationSeeded))
	}
	printInfoKV("passive discovered", fmt.Sprintf("%d", stats.PassiveDiscovered))
	printInfoKV("unique candidates", fmt.Sprintf("%d", stats.CandidateTotal))
	printInfoKV("resolved", fmt.Sprintf("%d, failed: %d", stats.ResolvedFast, stats.FailedFast))
	if stats.RDNSSeeded > 0 || stats.RDNSResolved > 0 {
		printInfoKV("reverse-dns expansion", fmt.Sprintf("seeded=%d, resolved=%d", stats.RDNSSeeded, stats.RDNSResolved))
	}
	printInfoKV("wildcard dropped", fmt.Sprintf("%d", stats.WildcardDropped))
	printInfoKV("trusted validation dropped", fmt.Sprintf("%d", stats.TrustedDropped))
	if stats.HTTPProbeEnabled {
		printInfoKV("http probed", fmt.Sprintf("%d", stats.HTTPProbed))
	}
	if stats.TakeoverEnabled {
		printInfoKV("takeover checked", fmt.Sprintf("%d", stats.TakeoverChecked))
		printInfoKV("takeover signals", fmt.Sprintf("%d", stats.TakeoverSignals))
	}
	printInfoKV("final subdomains", fmt.Sprintf("%d", stats.FinalTotal))

	if len(stats.SourceErrors) == 0 {
		return
	}
	if !verbose {
		printInfoKV("source warnings", fmt.Sprintf("%d (use --verbose for details)", len(stats.SourceErrors)))
		return
	}

	names := make([]string, 0, len(stats.SourceErrors))
	for name := range stats.SourceErrors {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(os.Stderr, "[INF] source warnings:")
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "[WARN] %s: %s\n", name, stats.SourceErrors[name])
	}
}

func printTopSourceYields(counts map[string]int, cacheHits map[string]int, limit int) {
	type row struct {
		name     string
		count    int
		cacheHit int
	}
	items := make([]row, 0, len(counts))
	for name, count := range counts {
		if count <= 0 {
			continue
		}
		items = append(items, row{name: name, count: count, cacheHit: cacheHits[name]})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, "[INF] top passive source yields: none")
		return
	}
	if limit < 1 {
		limit = 1
	}
	if len(items) > limit {
		items = items[:limit]
	}

	fmt.Fprintln(os.Stderr, "[INF] top passive source yields:")
	for _, item := range items {
		if item.cacheHit > 0 {
			fmt.Fprintf(os.Stderr, "[INF]   - %s: %d (cache hits: %d)\n", item.name, item.count, item.cacheHit)
			continue
		}
		fmt.Fprintf(os.Stderr, "[INF]   - %s: %d\n", item.name, item.count)
	}
}

func countPositiveSources(counts map[string]int) int {
	n := 0
	for _, count := range counts {
		if count > 0 {
			n++
		}
	}
	return n
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}

func printSources(names []string) {
	fmt.Printf("Available passive sources (%d):\n", len(names))
	for _, name := range names {
		fmt.Printf("- %s\n", name)
	}
}

func printList(items []string) {
	for _, item := range items {
		fmt.Println(item)
	}
}

func printResultSection(total int) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[INF] subdomain results")
	printInfoKV("total", fmt.Sprintf("%d", total))
	fmt.Fprintln(os.Stderr)
	if total == 0 {
		fmt.Fprintln(os.Stderr, "[INF] no subdomains found")
	}
}

func printInfoSection(title string) {
	fmt.Fprintln(os.Stderr, "[INF] "+title)
}

func printInfoKV(key, value string) {
	fmt.Fprintf(os.Stderr, "[INF] %-26s %s\n", key+":", value)
}

type takeoverFinding struct {
	Host     string
	Provider string
	Reason   string
}

type takeoverOnlySummary struct {
	Elapsed         time.Duration
	InputHosts      int
	ResolvedHosts   int
	UnresolvedHosts int
	TrustedDropped  int
	HTTPProbed      int
	TakeoverChecked int
	TakeoverSignals int
}

func filterTakeoverResults(results []model.Result) []model.Result {
	filtered := make([]model.Result, 0)
	for _, result := range results {
		if result.TakeoverPotential {
			filtered = append(filtered, result)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Host < filtered[j].Host })
	return filtered
}

func printTakeoverOnlySummary(summary takeoverOnlySummary, showHTTP bool) {
	printInfoSection("takeover scan summary")
	printInfoKV("elapsed", formatDuration(summary.Elapsed))
	printInfoKV("input hosts", fmt.Sprintf("%d", summary.InputHosts))
	printInfoKV("resolved hosts", fmt.Sprintf("%d", summary.ResolvedHosts))
	printInfoKV("unresolved hosts", fmt.Sprintf("%d", summary.UnresolvedHosts))
	printInfoKV("trusted validation dropped", fmt.Sprintf("%d", summary.TrustedDropped))
	if showHTTP {
		printInfoKV("http probed", fmt.Sprintf("%d", summary.HTTPProbed))
	}
	printInfoKV("takeover checked", fmt.Sprintf("%d", summary.TakeoverChecked))
	printInfoKV("takeover signals", fmt.Sprintf("%d", summary.TakeoverSignals))
}

func collectTakeoverFindings(results []model.Result) []takeoverFinding {
	findings := make([]takeoverFinding, 0)
	seen := map[string]struct{}{}
	for _, result := range results {
		if !result.TakeoverPotential {
			continue
		}
		host := strings.TrimSpace(result.Host)
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		findings = append(findings, takeoverFinding{
			Host:     host,
			Provider: strings.TrimSpace(result.TakeoverProvider),
			Reason:   strings.TrimSpace(result.TakeoverReason),
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Host < findings[j].Host })
	return findings
}

func printTakeoverAssessment(results []model.Result) {
	findings := collectTakeoverFindings(results)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "[INF] takeover assessment")
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "[INF] no luck: no takeover possibility detected")
		return
	}

	fmt.Fprintf(os.Stderr, "[INF] possible takeover targets (%d):\n", len(findings))
	for _, finding := range findings {
		provider := finding.Provider
		if provider == "" {
			provider = "unknown-provider"
		}
		reason := finding.Reason
		if reason == "" {
			reason = "signal matched"
		}
		fmt.Fprintf(os.Stderr, "[TAKEOVER] %s | provider=%s | reason=%s\n", finding.Host, provider, reason)
	}
}
