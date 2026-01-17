package htb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// TODO: Implement secure storage for tokens (e.g., OS keychain, encrypted file)
// For PoC, we use plain text files. This is NOT suitable for production.

// RefreshResponse represents the HTB token refresh API response
type RefreshResponse struct {
	Message struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"message"`
}

// TokenFiles holds paths to token storage files
type TokenFiles struct {
	AccessTokenPath  string
	RefreshTokenPath string
}

// DefaultTokenFiles returns default token file paths
func DefaultTokenFiles() TokenFiles {
	home, _ := os.UserHomeDir()
	return TokenFiles{
		AccessTokenPath:  home + "/.htb_token",
		RefreshTokenPath: home + "/.htb_refresh_token",
	}
}

// LoadTokenFromFile reads a token from a file
func LoadTokenFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read token file %s: %w", path, err)
	}
	// Trim whitespace/newlines
	token := string(bytes.TrimSpace(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
}

// SaveTokenToFile writes a token to a file with restrictive permissions
func SaveTokenToFile(path, token string) error {
	// Write with 0600 permissions (owner read/write only)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write token file %s: %w", path, err)
	}
	return nil
}

// RefreshTokens performs a token refresh against the HTB API
func RefreshTokens(accessToken, refreshToken string) (*RefreshResponse, error) {
	url := "https://labs.hackthebox.com/api/v4/login/refresh"

	payload := map[string]string{
		"refresh_token": refreshToken,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "htb-mcp-server/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	if result.Message.AccessToken == "" {
		return nil, fmt.Errorf("refresh response missing access_token")
	}

	return &result, nil
}

// RefreshAndSave performs a refresh and saves the new tokens to files
func RefreshAndSave(accessToken, refreshToken string, files TokenFiles) (*RefreshResponse, error) {
	result, err := RefreshTokens(accessToken, refreshToken)
	if err != nil {
		return nil, err
	}

	// Save new access token
	if err := SaveTokenToFile(files.AccessTokenPath, result.Message.AccessToken); err != nil {
		return nil, fmt.Errorf("failed to save access token: %w", err)
	}

	// Save new refresh token
	if err := SaveTokenToFile(files.RefreshTokenPath, result.Message.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return result, nil
}

// AutoRefreshIfNeeded checks token expiry and refreshes if expiring soon
// Returns the (possibly refreshed) access token and any error
func AutoRefreshIfNeeded(accessToken string, files TokenFiles, thresholdDays int) (string, bool, error) {
	status, err := ParseTokenExpiry(accessToken)
	if err != nil {
		return accessToken, false, fmt.Errorf("failed to parse token: %w", err)
	}

	// If token is expired or expiring within threshold, try to refresh
	if status.IsExpired || status.DaysLeft <= thresholdDays {
		refreshToken, err := LoadTokenFromFile(files.RefreshTokenPath)
		if err != nil {
			return accessToken, false, fmt.Errorf("token needs refresh but no refresh token available: %w", err)
		}

		result, err := RefreshAndSave(accessToken, refreshToken, files)
		if err != nil {
			return accessToken, false, fmt.Errorf("token refresh failed: %w", err)
		}

		return result.Message.AccessToken, true, nil
	}

	return accessToken, false, nil
}
