package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RuntimeOptions struct {
	Providers         map[string]string
	RateLimit         float64
	SourceRateLimits  map[string]float64
	SourceTimeout     time.Duration
	SourceTimeouts    map[string]time.Duration
	SourceRetries     int
	SourceBackoff     time.Duration
	SourceMaxBackoff  time.Duration
	SourceUserAgent   string
	EnableSourceStats bool
}

var (
	runtimeMu      sync.RWMutex
	runtimeOptions = RuntimeOptions{}
)

func ConfigureRuntime(opts RuntimeOptions) {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()

	cloned := opts
	cloned.Providers = copyStringMap(opts.Providers)
	cloned.SourceRateLimits = copyFloatMap(opts.SourceRateLimits)
	cloned.SourceTimeouts = copyDurationMap(opts.SourceTimeouts)

	if cloned.SourceRetries < 1 {
		cloned.SourceRetries = 1
	}
	if cloned.SourceBackoff <= 0 {
		cloned.SourceBackoff = 300 * time.Millisecond
	}
	if cloned.SourceMaxBackoff <= 0 {
		cloned.SourceMaxBackoff = 5 * time.Second
	}
	if strings.TrimSpace(cloned.SourceUserAgent) == "" {
		cloned.SourceUserAgent = "Subflare/1.0"
	}

	runtimeOptions = cloned
}

func runtimeSnapshot() RuntimeOptions {
	runtimeMu.RLock()
	defer runtimeMu.RUnlock()

	copy := runtimeOptions
	copy.Providers = copyStringMap(runtimeOptions.Providers)
	copy.SourceRateLimits = copyFloatMap(runtimeOptions.SourceRateLimits)
	copy.SourceTimeouts = copyDurationMap(runtimeOptions.SourceTimeouts)
	return copy
}

type runtimeClient struct {
	name      string
	client    *http.Client
	opts      RuntimeOptions
	rateLimit float64
	timeout   time.Duration
}

func newRuntimeClient(name string, client *http.Client) *runtimeClient {
	opts := runtimeSnapshot()
	rate := opts.RateLimit
	if sourceRate, ok := lookupSourceRate(opts.SourceRateLimits, name); ok && sourceRate > 0 {
		rate = sourceRate
	}
	timeout := opts.SourceTimeout
	if sourceTimeout, ok := lookupSourceTimeout(opts.SourceTimeouts, name); ok && sourceTimeout > 0 {
		timeout = sourceTimeout
	}
	return &runtimeClient{
		name:      name,
		client:    client,
		opts:      opts,
		rateLimit: rate,
		timeout:   timeout,
	}
}

func lookupSourceRate(m map[string]float64, name string) (float64, bool) {
	if value, ok := m[name]; ok {
		return value, true
	}
	if base := sourceBaseName(name); base != name {
		value, ok := m[base]
		return value, ok
	}
	return 0, false
}

func lookupSourceTimeout(m map[string]time.Duration, name string) (time.Duration, bool) {
	if value, ok := m[name]; ok {
		return value, true
	}
	if base := sourceBaseName(name); base != name {
		value, ok := m[base]
		return value, ok
	}
	return 0, false
}

func sourceBaseName(name string) string {
	if strings.HasSuffix(name, "_auth") {
		return strings.TrimSuffix(name, "_auth")
	}
	if strings.HasSuffix(name, "_unauth") {
		return strings.TrimSuffix(name, "_unauth")
	}
	return name
}

func (r *runtimeClient) ProviderValue(keys ...string) string {
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if value, ok := r.opts.Providers[trimmed]; ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
		upper := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(trimmed, ".", "_"), "-", "_"))
		if value, ok := r.opts.Providers[upper]; ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (r *runtimeClient) Get(ctx context.Context, url string, headers map[string]string) ([]byte, int, error) {
	attempts := r.opts.SourceRetries
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := r.waitRate(ctx); err != nil {
			return nil, 0, err
		}

		reqCtx := ctx
		cancel := func() {}
		if r.timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, r.timeout)
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, 0, err
		}
		if ua := strings.TrimSpace(r.opts.SourceUserAgent); ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		for key, value := range headers {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				continue
			}
			req.Header.Set(key, value)
		}

		resp, err := r.client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			if attempt < attempts {
				if sleepErr := r.sleepBackoff(ctx, attempt); sleepErr != nil {
					return nil, 0, sleepErr
				}
				continue
			}
			break
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if attempt < attempts {
				if sleepErr := r.sleepBackoff(ctx, attempt); sleepErr != nil {
					return nil, 0, sleepErr
				}
				continue
			}
			break
		}

		status := resp.StatusCode
		if status >= 200 && status <= 299 {
			return body, status, nil
		}

		if status == http.StatusTooManyRequests || status >= 500 {
			lastErr = fmt.Errorf("status %d", status)
			if attempt < attempts {
				if sleepErr := r.sleepBackoff(ctx, attempt); sleepErr != nil {
					return nil, status, sleepErr
				}
				continue
			}
		}
		return body, status, &StatusError{StatusCode: status, Body: body}
	}

	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, 0, lastErr
}

func (r *runtimeClient) waitRate(ctx context.Context) error {
	if r.rateLimit <= 0 {
		return nil
	}
	interval := time.Duration(float64(time.Second) / r.rateLimit)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	t := time.NewTimer(interval)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r *runtimeClient) sleepBackoff(ctx context.Context, attempt int) error {
	backoff := r.opts.SourceBackoff
	if backoff <= 0 {
		backoff = 300 * time.Millisecond
	}
	maxBackoff := r.opts.SourceMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Second
	}
	delay := backoff * time.Duration(1<<(attempt-1))
	if delay > maxBackoff {
		delay = maxBackoff
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type StatusError struct {
	StatusCode int
	Body       []byte
}

func (e *StatusError) Error() string {
	trimmed := strings.TrimSpace(string(e.Body))
	if len(trimmed) > 240 {
		trimmed = trimmed[:240]
	}
	if trimmed == "" {
		return fmt.Sprintf("unexpected status %d", e.StatusCode)
	}
	return fmt.Sprintf("unexpected status %d: %s", e.StatusCode, trimmed)
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyFloatMap(in map[string]float64) map[string]float64 {
	if len(in) == 0 {
		return map[string]float64{}
	}
	out := make(map[string]float64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyDurationMap(in map[string]time.Duration) map[string]time.Duration {
	if len(in) == 0 {
		return map[string]time.Duration{}
	}
	out := make(map[string]time.Duration, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
