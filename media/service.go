package media

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/bwmarrin/discordgo"
)

const DefaultService = "litterbox"

// Service defines a pluggable uploader for Discord attachments.
type Service interface {
	Name() string
	Upload(ctx context.Context, attachment *discordgo.MessageAttachment) (url string, statusCode int, err error)
}

// NewService returns the configured media upload backend. Currently only
// Litterbox is supported but the hook point allows future expansion.
func NewService(name string, httpClient *http.Client) (Service, error) {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		normalized = DefaultService
	}
	switch normalized {
	case DefaultService:
		return &LitterboxService{client: httpClient}, nil
	default:
		return nil, fmt.Errorf("unknown media upload service: %s", name)
	}
}
