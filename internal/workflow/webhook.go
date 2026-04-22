package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebhookConfig struct {
	URLs             []string
	DiscordURL       string
	SlackURL         string
	TelegramBotToken string
	TelegramChatID   string
	Timeout          time.Duration
}

func Dispatch(ctx context.Context, cfg WebhookConfig, domain string, diff Diff) []error {
	if len(diff.New) == 0 {
		return nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	message := fmt.Sprintf("Subflare monitor update for %s: new=%d removed=%d stable=%d", domain, len(diff.New), len(diff.Removed), len(diff.Stable))
	errs := []error{}

	for _, raw := range cfg.URLs {
		webhookURL := strings.TrimSpace(raw)
		if webhookURL == "" {
			continue
		}
		payload := map[string]any{
			"domain":       domain,
			"new":          diff.New,
			"removed":      diff.Removed,
			"stable_count": len(diff.Stable),
			"message":      message,
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		}
		if err := postJSON(ctx, webhookURL, payload, cfg.Timeout); err != nil {
			errs = append(errs, fmt.Errorf("webhook %s: %w", webhookURL, err))
		}
	}

	if strings.TrimSpace(cfg.DiscordURL) != "" {
		if err := postJSON(ctx, cfg.DiscordURL, map[string]string{"content": message}, cfg.Timeout); err != nil {
			errs = append(errs, fmt.Errorf("discord webhook: %w", err))
		}
	}
	if strings.TrimSpace(cfg.SlackURL) != "" {
		if err := postJSON(ctx, cfg.SlackURL, map[string]string{"text": message}, cfg.Timeout); err != nil {
			errs = append(errs, fmt.Errorf("slack webhook: %w", err))
		}
	}
	if strings.TrimSpace(cfg.TelegramBotToken) != "" && strings.TrimSpace(cfg.TelegramChatID) != "" {
		if err := sendTelegram(ctx, cfg, message); err != nil {
			errs = append(errs, fmt.Errorf("telegram webhook: %w", err))
		}
	}

	return errs
}

func postJSON(ctx context.Context, webhookURL string, payload any, timeout time.Duration) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Subflare/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func sendTelegram(ctx context.Context, cfg WebhookConfig, message string) error {
	form := url.Values{}
	form.Set("chat_id", cfg.TelegramChatID)
	form.Set("text", message)

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", strings.TrimSpace(cfg.TelegramBotToken))
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Subflare/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
