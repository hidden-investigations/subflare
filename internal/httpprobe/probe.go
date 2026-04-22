package httpprobe

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hidden-investigations/subflare/internal/model"
	"github.com/hidden-investigations/subflare/internal/util"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func ProbeResults(ctx context.Context, results []model.Result, threads int, timeout time.Duration) ([]model.Result, int) {
	if threads < 1 {
		threads = 1
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if len(results) == 0 {
		return results, 0
	}

	client := &http.Client{Timeout: timeout}
	jobs := make(chan int)
	out := make(chan model.Result, len(results))
	wg := sync.WaitGroup{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				item := results[idx]
				probeOne(ctx, client, &item)
				out <- item
			}
		}()
	}

	go func() {
		for idx := range results {
			jobs <- idx
		}
		close(jobs)
		wg.Wait()
		close(out)
	}()

	updated := make([]model.Result, 0, len(results))
	count := 0
	for item := range out {
		if item.HTTPStatus > 0 {
			count++
		}
		updated = append(updated, item)
	}

	// keep output stable by host ordering
	sort.Slice(updated, func(i, j int) bool { return updated[i].Host < updated[j].Host })
	return updated, count
}

func probeOne(ctx context.Context, client *http.Client, result *model.Result) {
	schemes := []string{"https://", "http://"}
	for _, scheme := range schemes {
		url := scheme + result.Host
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Subflare/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		result.HTTPURL = url
		result.HTTPStatus = resp.StatusCode
		result.HTTPTitle = extractTitle(string(body))
		result.HTTPTech = collectTech(resp.Header)
		return
	}
}

func extractTitle(body string) string {
	match := titleRe.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	title := strings.TrimSpace(htmlUnescape(match[1]))
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

func collectTech(header http.Header) []string {
	values := []string{}
	for _, key := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"} {
		v := strings.TrimSpace(header.Get(key))
		if v == "" {
			continue
		}
		values = append(values, key+": "+v)
	}
	return util.UniqueSorted(values)
}

func htmlUnescape(s string) string {
	replacer := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&amp;", "&",
		"&quot;", `"`,
		"&#39;", "'",
	)
	return replacer.Replace(s)
}
