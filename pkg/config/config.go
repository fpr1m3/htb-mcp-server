package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the HTB MCP Server
type Config struct {
	// HTB API Configuration
	HTBToken        string
	HTBRefreshToken string
	HTBBaseURL      string

	// Token file paths (for auto-refresh)
	TokenFilePath        string
	RefreshTokenFilePath string

	// Auto-refresh settings
	AutoRefresh          bool
	AutoRefreshThreshold int // Days before expiry to trigger refresh

	// Server Configuration
	ServerPort int
	LogLevel   string

	// Rate Limiting
	RateLimitPerMinute int

	// Caching
	CacheTTL time.Duration

	// Timeouts
	RequestTimeout time.Duration
}

// Load creates a new configuration from environment variables
func Load() (*Config, error) {
	home, _ := os.UserHomeDir()

	cfg := &Config{
		// Default values
		HTBBaseURL:           "https://labs.hackthebox.com/api/v4",
		ServerPort:           3000,
		LogLevel:             "INFO",
		RateLimitPerMinute:   100,
		CacheTTL:             5 * time.Minute,
		RequestTimeout:       30 * time.Second,
		AutoRefresh:          true,
		AutoRefreshThreshold: 7, // Refresh if expiring within 7 days
		TokenFilePath:        home + "/.htb_token",
		RefreshTokenFilePath: home + "/.htb_refresh_token",
	}

	// Override token file paths if specified
	if tokenFile := os.Getenv("HTB_TOKEN_FILE"); tokenFile != "" {
		cfg.TokenFilePath = tokenFile
	}
	if refreshFile := os.Getenv("HTB_REFRESH_TOKEN_FILE"); refreshFile != "" {
		cfg.RefreshTokenFilePath = refreshFile
	}

	// Try to load token from env first, then from file
	cfg.HTBToken = os.Getenv("HTB_TOKEN")
	if cfg.HTBToken == "" {
		// Try loading from file
		if tokenData, err := os.ReadFile(cfg.TokenFilePath); err == nil {
			cfg.HTBToken = string(tokenData)
			// Trim whitespace
			cfg.HTBToken = trimWhitespace(cfg.HTBToken)
		}
	}
	if cfg.HTBToken == "" {
		return nil, fmt.Errorf("HTB_TOKEN environment variable or token file (%s) is required", cfg.TokenFilePath)
	}

	// Try to load refresh token from env or file
	cfg.HTBRefreshToken = os.Getenv("HTB_REFRESH_TOKEN")
	if cfg.HTBRefreshToken == "" {
		if tokenData, err := os.ReadFile(cfg.RefreshTokenFilePath); err == nil {
			cfg.HTBRefreshToken = trimWhitespace(string(tokenData))
		}
	}

	// Auto-refresh setting
	if autoRefresh := os.Getenv("HTB_AUTO_REFRESH"); autoRefresh == "false" || autoRefresh == "0" {
		cfg.AutoRefresh = false
	}

	// Validate HTB token format (should be JWT with 3 parts)
	if err := validateHTBToken(cfg.HTBToken); err != nil {
		return nil, fmt.Errorf("invalid HTB_TOKEN format: %v", err)
	}

	// Optional environment variables
	if port := os.Getenv("SERVER_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.ServerPort = p
		}
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		cfg.LogLevel = logLevel
	}

	if rateLimit := os.Getenv("RATE_LIMIT_PER_MINUTE"); rateLimit != "" {
		if rl, err := strconv.Atoi(rateLimit); err == nil {
			cfg.RateLimitPerMinute = rl
		}
	}

	if cacheTTL := os.Getenv("CACHE_TTL_SECONDS"); cacheTTL != "" {
		if ttl, err := strconv.Atoi(cacheTTL); err == nil {
			cfg.CacheTTL = time.Duration(ttl) * time.Second
		}
	}

	if timeout := os.Getenv("REQUEST_TIMEOUT_SECONDS"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil {
			cfg.RequestTimeout = time.Duration(t) * time.Second
		}
	}

	return cfg, nil
}

// validateHTBToken checks if the token has the correct JWT format
func validateHTBToken(token string) error {
	// Basic JWT validation - should have 3 parts separated by dots
	parts := 0
	for _, char := range token {
		if char == '.' {
			parts++
		}
	}

	if parts != 2 {
		return fmt.Errorf("HTB token must be a valid JWT with 3 parts separated by dots")
	}

	return nil
}

// GetHTBAPIURL returns the full URL for an HTB API endpoint
func (c *Config) GetHTBAPIURL(endpoint string) string {
	return c.HTBBaseURL + endpoint
}

// trimWhitespace removes leading/trailing whitespace and newlines
func trimWhitespace(s string) string {
	return strings.TrimSpace(s)
}
