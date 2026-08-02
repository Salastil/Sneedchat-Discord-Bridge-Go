package config

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DiscordBotToken    string
	DiscordChannelID   string
	DiscordGuildID     string
	DiscordWebhookURL  string
	SneedchatRoomID    int
	MediaUploadService string
	BridgeUsername     string
	BridgePassword     string
	BridgeUserID       int
	DiscordPingUserID  string
	Debug              bool

	// KiwiScheme/KiwiHost address Kiwi Farms for the HTTP login/session
	// requests. KiwiHost may be set to a .onion address to log in over Tor.
	KiwiScheme string
	KiwiHost   string
	// SneedchatWSURL is the full WebSocket URL for the chat connection.
	// Defaults to the historical clearnet endpoint; set explicitly when
	// KiwiHost points at a .onion service with a different WS host/port.
	SneedchatWSURL string
	// TorSocksProxy, when non-empty (e.g. "127.0.0.1:9050"), routes all
	// Sneedchat traffic (login HTTP requests and the WebSocket connection)
	// through a Tor SOCKS5 proxy. Discord and media uploads are unaffected
	// and always go out on clearnet.
	TorSocksProxy string
	// KiwiTLSInsecureSkipVerify skips TLS certificate verification for
	// Kiwi Farms connections. Some .onion mirrors serve self-signed certs.
	KiwiTLSInsecureSkipVerify bool
}

func Load(envFile string) (*Config, error) {
	if err := godotenv.Load(envFile); err != nil {
		log.Printf("Warning: error loading %s: %v", envFile, err)
	}
	cfg := &Config{
		DiscordBotToken:    os.Getenv("DISCORD_BOT_TOKEN"),
		DiscordChannelID:   os.Getenv("DISCORD_CHANNEL_ID"),
		DiscordGuildID:     os.Getenv("DISCORD_GUILD_ID"),
		DiscordWebhookURL:  os.Getenv("DISCORD_WEBHOOK_URL"),
		MediaUploadService: os.Getenv("MEDIA_UPLOAD_SERVICE"),
		BridgeUsername:     os.Getenv("BRIDGE_USERNAME"),
		BridgePassword:     os.Getenv("BRIDGE_PASSWORD"),
		DiscordPingUserID:  os.Getenv("DISCORD_PING_USER_ID"),
		KiwiScheme:         os.Getenv("KIWIFARMS_SCHEME"),
		KiwiHost:           os.Getenv("KIWIFARMS_HOST"),
		SneedchatWSURL:     os.Getenv("SNEEDCHAT_WS_URL"),
		TorSocksProxy:      os.Getenv("TOR_SOCKS_PROXY"),
	}
	if cfg.MediaUploadService == "" {
		cfg.MediaUploadService = "litterbox"
	}
	if cfg.KiwiScheme == "" {
		cfg.KiwiScheme = "https"
	}
	if cfg.KiwiHost == "" {
		cfg.KiwiHost = "kiwifarms.st"
	}
	if cfg.SneedchatWSURL == "" {
		wsScheme := "wss"
		if cfg.KiwiScheme == "http" {
			wsScheme = "ws"
		}
		cfg.SneedchatWSURL = fmt.Sprintf("%s://%s:9443/chat.ws", wsScheme, cfg.KiwiHost)
	}
	roomID, err := strconv.Atoi(os.Getenv("SNEEDCHAT_ROOM_ID"))
	if err != nil {
		return nil, fmt.Errorf("invalid SNEEDCHAT_ROOM_ID: %w", err)
	}
	cfg.SneedchatRoomID = roomID
	if v := os.Getenv("BRIDGE_USER_ID"); v != "" {
		cfg.BridgeUserID, _ = strconv.Atoi(v)
	}
	if os.Getenv("DEBUG") == "1" || os.Getenv("DEBUG") == "true" {
		cfg.Debug = true
	}
	if os.Getenv("KIWIFARMS_TLS_INSECURE_SKIP_VERIFY") == "1" || os.Getenv("KIWIFARMS_TLS_INSECURE_SKIP_VERIFY") == "true" {
		cfg.KiwiTLSInsecureSkipVerify = true
	}
	return cfg, nil
}
