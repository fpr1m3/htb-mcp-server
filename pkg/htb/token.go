package htb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenStatus represents the status of an HTB JWT token
type TokenStatus struct {
	Valid       bool      `json:"valid"`
	ExpiresAt   time.Time `json:"expires_at"`
	ExpiresIn   string    `json:"expires_in"`
	DaysLeft    int       `json:"days_left"`
	IsExpired   bool      `json:"is_expired"`
	IsExpiring  bool      `json:"is_expiring"` // Within 7 days
	Warning     string    `json:"warning,omitempty"`
}

// jwtPayload represents the relevant fields from a JWT payload
// Note: HTB uses float64 timestamps (e.g., 1768609072.080649)
type jwtPayload struct {
	Exp float64 `json:"exp"`
	Iat float64 `json:"iat"`
	Sub string  `json:"sub"`
}

// ParseTokenExpiry extracts expiry information from an HTB JWT token
func ParseTokenExpiry(token string) (*TokenStatus, error) {
	status := &TokenStatus{
		Valid: false,
	}

	// Split JWT into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return status, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (middle part)
	payload := parts[1]

	// Add padding if needed (JWT base64 is unpadded)
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try standard encoding as fallback
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return status, fmt.Errorf("failed to decode JWT payload: %w", err)
		}
	}

	// Parse JSON payload
	var claims jwtPayload
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return status, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Check if exp claim exists
	if claims.Exp == 0 {
		return status, fmt.Errorf("JWT has no expiry claim")
	}

	// Calculate expiry (convert float64 timestamp to time.Time)
	expiresAt := time.Unix(int64(claims.Exp), 0)
	now := time.Now()
	duration := expiresAt.Sub(now)
	daysLeft := int(duration.Hours() / 24)

	status.Valid = true
	status.ExpiresAt = expiresAt
	status.DaysLeft = daysLeft
	status.IsExpired = now.After(expiresAt)
	status.IsExpiring = daysLeft <= 7 && daysLeft >= 0

	// Format expires_in string
	if status.IsExpired {
		status.ExpiresIn = "EXPIRED"
		status.Warning = fmt.Sprintf("Token expired %s ago", formatDuration(-duration))
	} else if daysLeft == 0 {
		status.ExpiresIn = fmt.Sprintf("%d hours", int(duration.Hours()))
		status.Warning = "Token expires TODAY"
	} else if daysLeft == 1 {
		status.ExpiresIn = "1 day"
		status.Warning = "Token expires TOMORROW"
	} else if status.IsExpiring {
		status.ExpiresIn = fmt.Sprintf("%d days", daysLeft)
		status.Warning = fmt.Sprintf("Token expires in %d days - consider refreshing", daysLeft)
	} else {
		status.ExpiresIn = fmt.Sprintf("%d days", daysLeft)
	}

	return status, nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}

	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%d hours", hours)
	}

	days := hours / 24
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

// CheckTokenHealth returns a summary suitable for logging
func CheckTokenHealth(token string) string {
	status, err := ParseTokenExpiry(token)
	if err != nil {
		return fmt.Sprintf("⚠️  Token validation failed: %v", err)
	}

	if status.IsExpired {
		return fmt.Sprintf("❌ Token EXPIRED %s ago - please refresh at https://app.hackthebox.com/profile/settings", formatDuration(time.Since(status.ExpiresAt)))
	}

	if status.IsExpiring {
		return fmt.Sprintf("⚠️  Token expires in %d days (on %s) - consider refreshing soon", status.DaysLeft, status.ExpiresAt.Format("2006-01-02"))
	}

	return fmt.Sprintf("✓ Token valid for %d days (expires %s)", status.DaysLeft, status.ExpiresAt.Format("2006-01-02"))
}
