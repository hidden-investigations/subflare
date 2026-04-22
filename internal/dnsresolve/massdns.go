package dnsresolve

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
)

func resolveWithMassDNS(ctx context.Context, candidates []model.Candidate, resolver *Resolver, cfg BackendConfig) ([]model.Result, int, error) {
	if len(candidates) == 0 {
		return nil, 0, nil
	}
	bin := strings.TrimSpace(cfg.MassDNSPath)
	if bin == "" {
		bin = "massdns"
	}

	tmpDir, err := os.MkdirTemp("", "subflare-massdns-*")
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(tmpDir)

	hostFile := filepath.Join(tmpDir, "hosts.txt")
	resolverFile := filepath.Join(tmpDir, "resolvers.txt")
	outputFile := filepath.Join(tmpDir, "out.txt")

	hostMap := map[string]model.Candidate{}
	hostLines := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		host := util.NormalizeHost(candidate.Host)
		if host == "" {
			continue
		}
		hostMap[host] = candidate
		hostLines = append(hostLines, host)
	}
	hostLines = util.UniqueSorted(hostLines)
	if len(hostLines) == 0 {
		return nil, 0, nil
	}
	if err := os.WriteFile(hostFile, []byte(strings.Join(hostLines, "\n")+"\n"), 0o600); err != nil {
		return nil, 0, err
	}

	servers := resolver.Servers()
	if len(servers) == 0 {
		return nil, 0, fmt.Errorf("no resolvers configured")
	}
	if err := os.WriteFile(resolverFile, []byte(strings.Join(servers, "\n")+"\n"), 0o600); err != nil {
		return nil, 0, err
	}

	cmd := exec.CommandContext(ctx, bin,
		"-r", resolverFile,
		"-t", "A",
		"-o", "S",
		"-w", outputFile,
		hostFile,
	)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, 0, fmt.Errorf("massdns run failed: %s", msg)
	}

	parsed, err := parseMassDNSOutput(outputFile)
	if err != nil {
		return nil, 0, err
	}

	results := make([]model.Result, 0, len(parsed))
	for host, rr := range parsed {
		candidate, ok := hostMap[host]
		if !ok {
			continue
		}
		result := model.Result{
			Host:             host,
			Sources:          model.SortedSources(candidate.Sources),
			SourceCount:      len(candidate.Sources),
			DuplicatesMerged: maxInt(len(candidate.Sources)-1, 0),
			Confidence:       confidenceFromSources(len(candidate.Sources)),
			FirstSeen:        time.Unix(candidate.FirstSeenUnix, 0).UTC().Format(time.RFC3339),
			IPs:              util.UniqueSorted(rr.IPs),
			CNAMEs:           util.UniqueSorted(rr.CNAMEs),
		}
		results = append(results, result)
	}

	failed := 0
	for _, host := range hostLines {
		if _, ok := parsed[host]; !ok {
			failed++
		}
	}
	return results, failed, nil
}

type massDNSRecord struct {
	IPs    []string
	CNAMEs []string
}

func parseMassDNSOutput(path string) (map[string]massDNSRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := map[string]massDNSRecord{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		host, typ, value, ok := parseMassDNSLine(line)
		if !ok {
			continue
		}
		record := out[host]
		switch typ {
		case "A":
			record.IPs = append(record.IPs, value)
		case "CNAME":
			record.CNAMEs = append(record.CNAMEs, value)
		}
		out[host] = record
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseMassDNSLine(line string) (host, typ, value string, ok bool) {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 3 {
		return "", "", "", false
	}
	host = strings.TrimSuffix(strings.ToLower(parts[0]), ".")
	typ = strings.ToUpper(strings.TrimSpace(parts[1]))
	value = strings.TrimSuffix(strings.TrimSpace(parts[2]), ".")
	if host == "" || value == "" {
		return "", "", "", false
	}
	if typ != "A" && typ != "CNAME" {
		return "", "", "", false
	}
	return host, typ, strings.ToLower(value), true
}
