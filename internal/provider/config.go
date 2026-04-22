package provider

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultRelativeConfig = ".config/subflare/providers.env"

func ResolvePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed != "" {
		return trimmed
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, defaultRelativeConfig)
}

func Load(path string) (map[string]string, error) {
	values := map[string]string{}

	resolved := ResolvePath(path)
	if resolved != "" {
		if fileInfo, err := os.Stat(resolved); err == nil && !fileInfo.IsDir() {
			fileValues, readErr := parseEnvFile(resolved)
			if readErr != nil {
				return nil, readErr
			}
			for key, value := range fileValues {
				values[key] = value
			}
		} else if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}

	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		if _, exists := values[key]; exists {
			continue
		}
		values[key] = value
	}

	return values, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid provider config line %d", lineNo)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, "\"")
		value = strings.Trim(value, "'")
		if key == "" || value == "" {
			continue
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return values, nil
}
