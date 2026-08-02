package config

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

const (
	kiwiClearnetHost = "kiwifarms.st"
	kiwiOnionHost    = "kiwifarmsaaf4t2h7gc3dfc5ojhmqruw2nit3uejrpiagrxeuxiyxcyd.onion"
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

	// TorEnabled routes the Sneedchat connection (login HTTP requests and
	// the chat WebSocket) through a bridge-managed Tor process to the Kiwi
	// Farms .onion address instead of clearnet. The bridge starts and stops
	// this Tor process itself — nothing external needs to be running.
	// Discord and media uploads are unaffected and always go out on
	// clearnet.
	TorEnabled bool

	// KiwiScheme/KiwiHost/SneedchatWSURL/KiwiTLSInsecureSkipVerify are
	// derived from TorEnabled, not set directly via the environment.
	KiwiScheme                string
	KiwiHost                  string
	SneedchatWSURL            string
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
	}
	if cfg.MediaUploadService == "" {
		cfg.MediaUploadService = "litterbox"
	}

	if v := os.Getenv("TOR"); v == "1" || v == "true" {
		cfg.TorEnabled = true
	}
	cfg.KiwiScheme = "https"
	if cfg.TorEnabled {
		cfg.KiwiHost = kiwiOnionHost
		// The .onion address itself authenticates the origin, so Kiwi
		// Farms' onion service doesn't need a CA-signed cert on top.
		cfg.KiwiTLSInsecureSkipVerify = true
	} else {
		cfg.KiwiHost = kiwiClearnetHost
	}
	cfg.SneedchatWSURL = fmt.Sprintf("wss://%s:9443/chat.ws", cfg.KiwiHost)

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
	return cfg, nil
}
