package options

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	defaultResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	defaultTrusted   = []string{"1.1.1.1:53", "8.8.8.8:53"}
)

// Options contains CLI configuration for a scan.
type Options struct {
	Domain           string
	Passive          bool
	Bruteforce       bool
	Wordlist         string
	Sources          []string
	ExcludeSources   []string
	ListSources      bool
	NoBanner         bool
	ProviderConfig   string
	RateLimit        float64
	SourceRateLimits map[string]float64
	SourceTimeout    time.Duration
	SourceTimeouts   map[string]time.Duration
	SourceRetries    int
	SourceBackoff    time.Duration
	SourceMaxBackoff time.Duration
	CacheDir         string
	CacheTTL         time.Duration
	NoCache          bool
	Stdin            bool
	StrictIO         bool
	WebhookURLs      []string
	DiscordWebhook   string
	SlackWebhook     string
	TelegramBotToken string
	TelegramChatID   string
	WebhookTimeout   time.Duration
	MonitorInterval  time.Duration
	MonitorCycles    int
	StateDir         string
	Resolvers        []string
	TrustedResolvers []string
	Threads          int
	Timeout          time.Duration
	Retries          int
	HTTPTimeout      time.Duration
	WildcardTests    int
	Output           string
	JSONL            string
	Silent           bool
	Verbose          bool
}

func Parse(fs *flag.FlagSet, args []string) (Options, error) {
	opts := Options{}
	var resolversInput string
	var trustedInput string
	var sourcesInput string
	var excludeSourcesInput string
	var sourceRateInput string
	var sourceTimeoutInput string
	var webhookInput string

	fs.StringVar(&opts.Domain, "domain", "", "target root domain")
	fs.StringVar(&opts.Domain, "d", "", "target root domain")
	fs.BoolVar(&opts.Passive, "passive", true, "enable passive source enumeration")
	fs.BoolVar(&opts.Bruteforce, "bruteforce", false, "enable wordlist bruteforce")
	fs.StringVar(&opts.Wordlist, "wordlist", "", "wordlist file path for bruteforce")
	fs.StringVar(&opts.Wordlist, "w", "", "wordlist file path for bruteforce")
	fs.StringVar(&sourcesInput, "sources", "", "comma-separated passive source names")
	fs.StringVar(&sourcesInput, "s", "", "comma-separated passive source names")
	fs.StringVar(&excludeSourcesInput, "exclude-sources", "", "comma-separated passive sources to exclude")
	fs.StringVar(&excludeSourcesInput, "es", "", "comma-separated passive sources to exclude")
	fs.BoolVar(&opts.ListSources, "list-sources", false, "list passive sources and exit")
	fs.BoolVar(&opts.NoBanner, "no-banner", false, "suppress startup banner")
	fs.StringVar(&opts.ProviderConfig, "provider-config", "", "provider config file path (default: ~/.config/subflare/providers.env)")
	fs.Float64Var(&opts.RateLimit, "rate-limit", 0, "global passive-source request rate limit in req/sec (0=unlimited)")
	fs.StringVar(&sourceRateInput, "rate-limit-source", "", "per-source request limits, e.g. 'crtsh=5/s,shodan=2/s'")
	fs.StringVar(&sourceRateInput, "rls", "", "per-source request limits, e.g. 'crtsh=5/s,shodan=2/s'")
	fs.DurationVar(&opts.SourceTimeout, "source-timeout", 20*time.Second, "per-source request timeout")
	fs.StringVar(&sourceTimeoutInput, "source-timeout-source", "", "per-source timeout overrides, e.g. 'anubis=10s,rapiddns=25s'")
	fs.IntVar(&opts.SourceRetries, "source-retries", 2, "request retries per passive source")
	fs.DurationVar(&opts.SourceBackoff, "source-backoff", 300*time.Millisecond, "base retry backoff for passive sources")
	fs.DurationVar(&opts.SourceMaxBackoff, "source-max-backoff", 5*time.Second, "max retry backoff for passive sources")
	fs.StringVar(&opts.CacheDir, "cache-dir", "", "cache directory for passive source responses (default: ~/.cache/subflare)")
	fs.DurationVar(&opts.CacheTTL, "cache-ttl", 24*time.Hour, "cache TTL for passive source responses")
	fs.BoolVar(&opts.NoCache, "no-cache", false, "disable passive-source cache usage")
	fs.BoolVar(&opts.Stdin, "stdin", false, "read domains from stdin (one per line)")
	fs.BoolVar(&opts.StrictIO, "strict-io", false, "strict automation mode (no banner/stats, output only results)")
	fs.StringVar(&webhookInput, "webhook", "", "comma-separated generic webhook URLs")
	fs.StringVar(&opts.DiscordWebhook, "webhook-discord", "", "discord webhook URL")
	fs.StringVar(&opts.SlackWebhook, "webhook-slack", "", "slack webhook URL")
	fs.StringVar(&opts.TelegramBotToken, "webhook-telegram-bot", "", "telegram bot token")
	fs.StringVar(&opts.TelegramChatID, "webhook-telegram-chat", "", "telegram chat id")
	fs.DurationVar(&opts.WebhookTimeout, "webhook-timeout", 10*time.Second, "webhook request timeout")
	fs.DurationVar(&opts.MonitorInterval, "monitor-interval", 10*time.Minute, "monitor mode interval")
	fs.IntVar(&opts.MonitorCycles, "monitor-cycles", 0, "monitor mode cycles (0=infinite)")
	fs.StringVar(&opts.StateDir, "state-dir", "", "state directory for monitor snapshots")
	fs.StringVar(&resolversInput, "resolvers", "", "comma-separated resolvers or file path")
	fs.StringVar(&resolversInput, "r", "", "comma-separated resolvers or file path")
	fs.StringVar(&trustedInput, "trusted-resolvers", "", "comma-separated trusted resolvers or file path")
	fs.StringVar(&trustedInput, "tr", "", "comma-separated trusted resolvers or file path")
	fs.IntVar(&opts.Threads, "threads", 200, "number of concurrent DNS workers")
	fs.IntVar(&opts.Threads, "t", 200, "number of concurrent DNS workers")
	fs.DurationVar(&opts.Timeout, "timeout", 3*time.Second, "per-request DNS timeout")
	fs.IntVar(&opts.Retries, "retries", 2, "DNS retries per host")
	fs.DurationVar(&opts.HTTPTimeout, "http-timeout", 25*time.Second, "http client timeout for passive sources")
	fs.IntVar(&opts.WildcardTests, "wildcard-tests", 2, "random checks per suffix during wildcard detection")
	fs.StringVar(&opts.Output, "output", "", "optional text output file")
	fs.StringVar(&opts.Output, "o", "", "optional text output file")
	fs.StringVar(&opts.JSONL, "jsonl", "", "optional JSONL output file")
	fs.BoolVar(&opts.Silent, "silent", false, "print only subdomains to stdout")
	fs.BoolVar(&opts.Verbose, "verbose", false, "show detailed warnings")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}

	opts.Sources = parseCSV(sourcesInput)
	opts.ExcludeSources = parseCSV(excludeSourcesInput)
	opts.WebhookURLs = parseCSVRaw(webhookInput)
	sourceRates, err := parseRateMap(sourceRateInput)
	if err != nil {
		return opts, fmt.Errorf("parse rate-limit-source: %w", err)
	}
	opts.SourceRateLimits = sourceRates
	sourceTimeouts, err := parseDurationMap(sourceTimeoutInput)
	if err != nil {
		return opts, fmt.Errorf("parse source-timeout-source: %w", err)
	}
	opts.SourceTimeouts = sourceTimeouts

	if opts.ListSources {
		return opts, nil
	}

	opts.Domain = normalizeDomain(opts.Domain)
	if opts.Domain == "" && !opts.Stdin {
		return opts, errors.New("domain is required (use -d example.com)")
	}
	if opts.Threads < 1 {
		return opts, errors.New("threads must be > 0")
	}
	if opts.Retries < 1 {
		return opts, errors.New("retries must be > 0")
	}
	if opts.WildcardTests < 1 {
		return opts, errors.New("wildcard-tests must be > 0")
	}
	if opts.SourceRetries < 1 {
		return opts, errors.New("source-retries must be > 0")
	}
	if opts.SourceTimeout <= 0 {
		return opts, errors.New("source-timeout must be > 0")
	}
	if opts.SourceBackoff <= 0 {
		return opts, errors.New("source-backoff must be > 0")
	}
	if opts.SourceMaxBackoff <= 0 {
		return opts, errors.New("source-max-backoff must be > 0")
	}
	if opts.CacheTTL <= 0 {
		return opts, errors.New("cache-ttl must be > 0")
	}
	if opts.WebhookTimeout <= 0 {
		return opts, errors.New("webhook-timeout must be > 0")
	}
	if opts.MonitorInterval <= 0 {
		return opts, errors.New("monitor-interval must be > 0")
	}
	if opts.MonitorCycles < 0 {
		return opts, errors.New("monitor-cycles cannot be negative")
	}
	if opts.RateLimit < 0 {
		return opts, errors.New("rate-limit cannot be negative")
	}

	if opts.Wordlist != "" {
		opts.Bruteforce = true
	}
	if opts.Bruteforce && opts.Wordlist == "" {
		return opts, errors.New("bruteforce enabled but no wordlist supplied")
	}
	if !opts.Passive && !opts.Bruteforce {
		return opts, errors.New("enable at least one mode: passive or bruteforce")
	}

	resolvers, err := parseResolverInput(resolversInput)
	if err != nil {
		return opts, fmt.Errorf("parse resolvers: %w", err)
	}
	if len(resolvers) == 0 {
		resolvers = append([]string{}, defaultResolvers...)
	}

	trusted, err := parseResolverInput(trustedInput)
	if err != nil {
		return opts, fmt.Errorf("parse trusted resolvers: %w", err)
	}
	if len(trusted) == 0 {
		trusted = append([]string{}, defaultTrusted...)
	}

	opts.Resolvers = normalizeResolvers(resolvers)
	opts.TrustedResolvers = normalizeResolvers(trusted)

	return opts, nil
}

func PrintHelp(w io.Writer, sourceNames []string) {
	list := append([]string{}, sourceNames...)
	sort.Strings(list)
	joined := strings.Join(list, ", ")

	fmt.Fprintln(w, "Subflare - Modern Subdomain Recon Tool")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  subflare               run subdomain scan")
	fmt.Fprintln(w, "  subflare bench         benchmark passive collection and DNS resolve throughput")
	fmt.Fprintln(w, "  subflare diff          compare old/new result files")
	fmt.Fprintln(w, "  subflare monitor       run scheduled scans with diffing")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  subflare -d example.com [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Core Flags:")
	fmt.Fprintln(w, "  -d, --domain string         target root domain")
	fmt.Fprintln(w, "  --passive                   enable passive source enumeration (default: true)")
	fmt.Fprintln(w, "  --bruteforce                enable wordlist bruteforce")
	fmt.Fprintln(w, "  -w, --wordlist string       wordlist file path for bruteforce")
	fmt.Fprintln(w, "  -s, --sources string        comma-separated passive sources to run")
	fmt.Fprintln(w, "  -es, --exclude-sources      comma-separated passive sources to skip")
	fmt.Fprintln(w, "  --list-sources              list all passive sources and exit")
	fmt.Fprintln(w, "  --provider-config string    provider config file path")
	fmt.Fprintln(w, "  --no-banner                 hide banner (automation friendly)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Passive Performance Flags:")
	fmt.Fprintln(w, "  --rate-limit float          global request rate limit in req/sec")
	fmt.Fprintln(w, "  --rls string                per-source rate limits, e.g. 'crtsh=5/s,shodan=2/s'")
	fmt.Fprintln(w, "  --source-timeout duration   request timeout for passive sources")
	fmt.Fprintln(w, "  --source-timeout-source     per-source timeout override map")
	fmt.Fprintln(w, "  --source-retries int        retries per source request")
	fmt.Fprintln(w, "  --source-backoff duration   base backoff between source retries")
	fmt.Fprintln(w, "  --source-max-backoff        max backoff between source retries")
	fmt.Fprintln(w, "  --cache-dir string          cache directory for passive responses")
	fmt.Fprintln(w, "  --cache-ttl duration        cache validity for passive responses")
	fmt.Fprintln(w, "  --no-cache                  disable passive-source cache")
	fmt.Fprintln(w, "  --stdin                     read domains from stdin")
	fmt.Fprintln(w, "  --strict-io                 machine-friendly output mode")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Workflow Flags:")
	fmt.Fprintln(w, "  --monitor-interval duration monitor scan interval")
	fmt.Fprintln(w, "  --monitor-cycles int        monitor cycles (0=infinite)")
	fmt.Fprintln(w, "  --state-dir string          monitor state directory")
	fmt.Fprintln(w, "  --webhook string            generic webhook URL list")
	fmt.Fprintln(w, "  --webhook-discord string    discord webhook URL")
	fmt.Fprintln(w, "  --webhook-slack string      slack webhook URL")
	fmt.Fprintln(w, "  --webhook-telegram-bot      telegram bot token")
	fmt.Fprintln(w, "  --webhook-telegram-chat     telegram chat id")
	fmt.Fprintln(w, "  --webhook-timeout duration  webhook timeout")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "DNS Flags:")
	fmt.Fprintln(w, "  -r, --resolvers string      resolvers file path or comma-separated resolvers")
	fmt.Fprintln(w, "  -tr, --trusted-resolvers    trusted resolvers file path or comma-separated resolvers")
	fmt.Fprintln(w, "  -t, --threads int           concurrent DNS workers (default: 200)")
	fmt.Fprintln(w, "  --timeout duration          per-request DNS timeout (default: 3s)")
	fmt.Fprintln(w, "  --retries int               DNS retries per host (default: 2)")
	fmt.Fprintln(w, "  --wildcard-tests int        random checks per suffix (default: 2)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Output Flags:")
	fmt.Fprintln(w, "  -o, --output string         save subdomains as text")
	fmt.Fprintln(w, "  --jsonl string              save structured JSONL output")
	fmt.Fprintln(w, "  --silent                    print only subdomains to stdout")
	fmt.Fprintln(w, "  --verbose                   print warning details")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  subflare -d example.com")
	fmt.Fprintln(w, "  subflare -d example.com --sources crtsh,anubis,rapiddns")
	fmt.Fprintln(w, "  subflare -d example.com -es shodan --rls 'crtsh=5/s,rapiddns=2/s'")
	fmt.Fprintln(w, "  subflare -d example.com --provider-config ~/.config/subflare/providers.env")
	fmt.Fprintln(w, "  subflare -d example.com --silent --no-banner -o results.txt --jsonl results.jsonl")
	fmt.Fprintln(w, "  cat domains.txt | subflare --stdin --strict-io --no-banner")
	fmt.Fprintln(w, "  subflare monitor -d example.com --monitor-interval 15m")
	fmt.Fprintln(w, "  subflare diff --old old.txt --new new.txt")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Passive Sources (%d): %s\n", len(list), joined)
}

func RawNoBanner(args []string) bool {
	for _, raw := range args {
		arg := strings.TrimSpace(raw)
		if arg == "--no-banner" || arg == "-no-banner" {
			return true
		}
		if strings.HasPrefix(arg, "--no-banner=") {
			return parseRawBool(strings.TrimPrefix(arg, "--no-banner="))
		}
		if strings.HasPrefix(arg, "-no-banner=") {
			return parseRawBool(strings.TrimPrefix(arg, "-no-banner="))
		}
	}
	return false
}

func RawStrictIO(args []string) bool {
	for _, raw := range args {
		arg := strings.TrimSpace(raw)
		if arg == "--strict-io" || arg == "-strict-io" {
			return true
		}
		if strings.HasPrefix(arg, "--strict-io=") {
			return parseRawBool(strings.TrimPrefix(arg, "--strict-io="))
		}
		if strings.HasPrefix(arg, "-strict-io=") {
			return parseRawBool(strings.TrimPrefix(arg, "-strict-io="))
		}
	}
	return false
}

func parseRawBool(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return true
	}
	return parsed
}

func normalizeDomain(input string) string {
	trimmed := strings.TrimSpace(strings.ToLower(input))
	trimmed = strings.TrimPrefix(trimmed, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimSuffix(trimmed, "/")
	trimmed = strings.TrimPrefix(trimmed, "*.")
	trimmed = strings.TrimSuffix(trimmed, ".")
	return trimmed
}

func parseResolverInput(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	if fileInfo, err := os.Stat(input); err == nil && !fileInfo.IsDir() {
		return readLines(input)
	}
	if strings.Contains(input, ",") {
		parts := strings.Split(input, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			value := strings.TrimSpace(part)
			if value != "" {
				out = append(out, value)
			}
		}
		return out, nil
	}
	return []string{input}, nil
}

func normalizeResolvers(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, ":") {
			item += ":53"
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func parseCSV(input string) []string {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range strings.Split(input, ",") {
		value := strings.TrimSpace(strings.ToLower(item))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func parseCSVRaw(input string) []string {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range strings.Split(input, ",") {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func parseDurationMap(input string) (map[string]time.Duration, error) {
	out := map[string]time.Duration{}
	input = strings.TrimSpace(input)
	if input == "" {
		return out, nil
	}
	parts := strings.Split(input, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid entry %q", part)
		}
		name := strings.TrimSpace(strings.ToLower(kv[0]))
		value := strings.TrimSpace(kv[1])
		if name == "" || value == "" {
			return nil, fmt.Errorf("invalid entry %q", part)
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if duration <= 0 {
			return nil, fmt.Errorf("%s: duration must be > 0", name)
		}
		out[name] = duration
	}
	return out, nil
}

func parseRateMap(input string) (map[string]float64, error) {
	out := map[string]float64{}
	input = strings.TrimSpace(input)
	if input == "" {
		return out, nil
	}
	parts := strings.Split(input, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid entry %q", part)
		}
		name := strings.TrimSpace(strings.ToLower(kv[0]))
		value := strings.TrimSpace(kv[1])
		rate, err := parseRateValue(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = rate
	}
	return out, nil
}

func parseRateValue(input string) (float64, error) {
	value := strings.TrimSpace(strings.ToLower(input))
	if value == "" {
		return 0, errors.New("empty rate")
	}
	multiplier := 1.0
	if strings.HasSuffix(value, "/s") {
		value = strings.TrimSuffix(value, "/s")
		multiplier = 1.0
	} else if strings.HasSuffix(value, "/m") {
		value = strings.TrimSuffix(value, "/m")
		multiplier = 1.0 / 60.0
	} else if strings.HasSuffix(value, "/h") {
		value = strings.TrimSuffix(value, "/h")
		multiplier = 1.0 / 3600.0
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, err
	}
	if parsed < 0 {
		return 0, errors.New("rate cannot be negative")
	}
	return parsed * multiplier, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
