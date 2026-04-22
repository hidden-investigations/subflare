package source

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Source defines passive subdomain data sources.
type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

type BuildOptions struct {
	HTTPTimeout     time.Duration
	Requested       []string
	Excluded        []string
	Runtime         RuntimeOptions
	RespectOrdering bool
}

type sourceFactory struct {
	name    string
	aliases []string
	build   func(client *http.Client) Source
}

var factories = []sourceFactory{
	{name: "alienvault", aliases: []string{"otx"}, build: func(c *http.Client) Source { return NewAlienVault(c) }},
	{name: "hackertarget", build: func(c *http.Client) Source { return NewHackerTarget(c) }},
	{name: "rapiddns", build: func(c *http.Client) Source { return NewRapidDNS(c) }},
	{name: "leakix", build: func(c *http.Client) Source { return NewLeakIX(c) }},
	{name: "certspotter", build: func(c *http.Client) Source { return NewCertSpotter(c) }},
	{name: "crtsh", aliases: []string{"crt.sh"}, build: func(c *http.Client) Source { return NewCRTSh(c) }},
	{name: "anubis", build: func(c *http.Client) Source { return NewAnubis(c) }},
	{name: "shodan", build: func(c *http.Client) Source { return NewShodan(c) }},
	{name: "commoncrawl", aliases: []string{"common-crawl"}, build: func(c *http.Client) Source { return NewCommonCrawl(c) }},
	{name: "waybackarchive", aliases: []string{"wayback", "archiveorg"}, build: func(c *http.Client) Source { return NewWaybackArchive(c) }},
	{name: "digitorus", aliases: []string{"certificatedetails"}, build: func(c *http.Client) Source { return NewDigitorus(c) }},
	{name: "riddler", aliases: []string{"riddlerio"}, build: func(c *http.Client) Source { return NewRiddler(c) }},
	{name: "threatcrowd", build: func(c *http.Client) Source { return NewThreatCrowd(c) }},
	{name: "threatminer", build: func(c *http.Client) Source { return NewThreatMiner(c) }},
	{name: "sitedossier", aliases: []string{"site-dossier"}, build: func(c *http.Client) Source { return NewSiteDossier(c) }},
	{name: "securitytrails", aliases: []string{"security-trails"}, build: func(c *http.Client) Source { return NewSecurityTrails(c) }},
	{name: "virustotal", aliases: []string{"vt"}, build: func(c *http.Client) Source { return NewVirusTotal(c) }},
	{name: "censys", build: func(c *http.Client) Source { return NewCensys(c) }},
	{name: "whoisxmlapi", aliases: []string{"whoisxml"}, build: func(c *http.Client) Source { return NewWhoisXMLAPI(c) }},
	{name: "chaos", aliases: []string{"pdchaos"}, build: func(c *http.Client) Source { return NewChaos(c) }},
	{name: "github", aliases: []string{"githubcode"}, build: func(c *http.Client) Source { return NewGitHub(c) }},
	{name: "gitlab", aliases: []string{"gitlabcode"}, build: func(c *http.Client) Source { return NewGitLab(c) }},
	{name: "netlas", build: func(c *http.Client) Source { return NewNetlas(c) }},
	{name: "fofa", build: func(c *http.Client) Source { return NewFOFA(c) }},
	{name: "zoomeyeapi", aliases: []string{"zoomeye"}, build: func(c *http.Client) Source { return NewZoomEyeAPI(c) }},
}

func NewDefaultSources(httpTimeout time.Duration) ([]Source, error) {
	return BuildSources(BuildOptions{HTTPTimeout: httpTimeout})
}

func NewSourcesByName(httpTimeout time.Duration, requested []string) ([]Source, error) {
	return BuildSources(BuildOptions{HTTPTimeout: httpTimeout, Requested: requested})
}

func BuildSources(opts BuildOptions) ([]Source, error) {
	ConfigureRuntime(opts.Runtime)
	client := &http.Client{Timeout: opts.HTTPTimeout}

	excluded := normalizeList(opts.Excluded)
	excludedSet := map[string]struct{}{}
	for _, item := range excluded {
		excludedSet[item] = struct{}{}
	}

	lookup := make(map[string]sourceFactory, len(factories)*2)
	for _, factory := range factories {
		lookup[factory.name] = factory
		for _, alias := range factory.aliases {
			lookup[alias] = factory
		}
	}

	selected := opts.Requested
	if len(selected) == 0 {
		selected = AvailableSourceNames()
	}
	selected = normalizeList(selected)

	seen := map[string]struct{}{}
	sources := []Source{}
	unknown := []string{}

	for _, item := range selected {
		factory, ok := lookup[item]
		if !ok {
			unknown = append(unknown, item)
			continue
		}
		if _, excluded := excludedSet[factory.name]; excluded {
			continue
		}
		if _, exists := seen[factory.name]; exists {
			continue
		}
		seen[factory.name] = struct{}{}
		sources = append(sources, factory.build(client))
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown source(s): %s (available: %s)", strings.Join(unknown, ","), strings.Join(AvailableSourceNames(), ","))
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("no valid passive sources selected")
	}

	if !opts.RespectOrdering {
		sort.SliceStable(sources, func(i, j int) bool {
			return sources[i].Name() < sources[j].Name()
		})
	}

	return sources, nil
}

func AvailableSourceNames() []string {
	names := make([]string, 0, len(factories))
	for _, factory := range factories {
		names = append(names, factory.name)
	}
	return names
}

func normalizeList(input []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range input {
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
