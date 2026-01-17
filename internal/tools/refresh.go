package tools

import (
	"context"
	"fmt"

	"github.com/NoASLR/htb-mcp-server/pkg/htb"
	"github.com/NoASLR/htb-mcp-server/pkg/mcp"
)

// RefreshToken tool for refreshing HTB API tokens
type RefreshToken struct {
	client       *htb.Client
	accessToken  string
	refreshToken string
	tokenFiles   htb.TokenFiles
}

func NewRefreshToken(client *htb.Client, accessToken, refreshToken string, tokenFiles htb.TokenFiles) *RefreshToken {
	return &RefreshToken{
		client:       client,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		tokenFiles:   tokenFiles,
	}
}

func (t *RefreshToken) Name() string {
	return "refresh_token"
}

func (t *RefreshToken) Description() string {
	return "Refresh the HTB API access token using the refresh token. Saves new tokens to disk."
}

func (t *RefreshToken) Schema() mcp.ToolSchema {
	return mcp.ToolSchema{
		Type: "object",
		Properties: map[string]mcp.Property{
			"force": {
				Type:        "boolean",
				Description: "Force refresh even if token is not expiring",
				Default:     false,
			},
		},
	}
}

func (t *RefreshToken) Execute(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResponse, error) {
	force := false
	if f, ok := args["force"].(bool); ok {
		force = f
	}

	// Check current token status
	status, err := htb.ParseTokenExpiry(t.accessToken)
	if err != nil {
		content := mcp.CreateTextContent(fmt.Sprintf("Failed to parse current token: %v", err))
		return &mcp.CallToolResponse{
			Content: []mcp.Content{content},
			IsError: true,
		}, nil
	}

	// Only refresh if needed or forced
	if !force && !status.IsExpired && !status.IsExpiring {
		result := map[string]interface{}{
			"refreshed":    false,
			"reason":       "Token still valid and not expiring soon",
			"days_left":    status.DaysLeft,
			"expires_at":   status.ExpiresAt,
			"hint":         "Use force=true to refresh anyway",
		}
		content, err := mcp.CreateJSONContent(result)
		if err != nil {
			return nil, err
		}
		return &mcp.CallToolResponse{
			Content: []mcp.Content{content},
		}, nil
	}

	// Load refresh token from file if not provided
	refreshToken := t.refreshToken
	if refreshToken == "" {
		refreshToken, err = htb.LoadTokenFromFile(t.tokenFiles.RefreshTokenPath)
		if err != nil {
			content := mcp.CreateTextContent(fmt.Sprintf("No refresh token available: %v", err))
			return &mcp.CallToolResponse{
				Content: []mcp.Content{content},
				IsError: true,
			}, nil
		}
	}

	// Perform refresh
	refreshResult, err := htb.RefreshAndSave(t.accessToken, refreshToken, t.tokenFiles)
	if err != nil {
		content := mcp.CreateTextContent(fmt.Sprintf("Token refresh failed: %v", err))
		return &mcp.CallToolResponse{
			Content: []mcp.Content{content},
			IsError: true,
		}, nil
	}

	// Parse new token for status
	newStatus, _ := htb.ParseTokenExpiry(refreshResult.Message.AccessToken)

	result := map[string]interface{}{
		"refreshed":        true,
		"new_expires_at":   newStatus.ExpiresAt,
		"new_days_left":    newStatus.DaysLeft,
		"tokens_saved_to": map[string]string{
			"access_token":  t.tokenFiles.AccessTokenPath,
			"refresh_token": t.tokenFiles.RefreshTokenPath,
		},
		"note": "Restart server to use new token, or it will be used on next startup",
	}

	content, err := mcp.CreateJSONContent(result)
	if err != nil {
		return nil, err
	}

	return &mcp.CallToolResponse{
		Content: []mcp.Content{content},
	}, nil
}
