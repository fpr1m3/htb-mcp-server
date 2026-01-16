package tools

import (
	"context"

	"github.com/NoASLR/htb-mcp-server/pkg/htb"
	"github.com/NoASLR/htb-mcp-server/pkg/mcp"
)

// GetTokenStatus tool for checking HTB token validity and expiry
type GetTokenStatus struct {
	client *htb.Client
	token  string
}

func NewGetTokenStatus(client *htb.Client, token string) *GetTokenStatus {
	return &GetTokenStatus{client: client, token: token}
}

func (t *GetTokenStatus) Name() string {
	return "get_token_status"
}

func (t *GetTokenStatus) Description() string {
	return "Check HTB API token validity and expiration status"
}

func (t *GetTokenStatus) Schema() mcp.ToolSchema {
	return mcp.ToolSchema{
		Type:       "object",
		Properties: map[string]mcp.Property{},
	}
}

func (t *GetTokenStatus) Execute(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResponse, error) {
	// Parse token expiry
	status, err := htb.ParseTokenExpiry(t.token)
	if err != nil {
		// Return error as content, not as tool failure
		content := mcp.CreateTextContent("Token validation failed: " + err.Error())
		return &mcp.CallToolResponse{
			Content: []mcp.Content{content},
		}, nil
	}

	// Also verify API connectivity
	apiStatus := "connected"
	if err := t.client.HealthCheck(ctx); err != nil {
		apiStatus = "error: " + err.Error()
	}

	// Build response
	result := map[string]interface{}{
		"token_status": status,
		"api_status":   apiStatus,
		"refresh_url":  "https://app.hackthebox.com/profile/settings",
	}

	content, err := mcp.CreateJSONContent(result)
	if err != nil {
		return nil, err
	}

	return &mcp.CallToolResponse{
		Content: []mcp.Content{content},
	}, nil
}
