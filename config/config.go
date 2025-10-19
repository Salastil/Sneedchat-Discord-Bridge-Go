package config

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DiscordBotToken   string
	DiscordChannelID  string
	DiscordGuildID    string
	DiscordWebhookURL string
	SneedchatRoomID   int
	BridgeUsername    string
	BridgePassword    string
	BridgeUserID      int
	DiscordPingUserID string
	Debug             bool
}

func Load(envFile string) (*Config, error) {
	if err := godotenv.Load(envFile); err != nil {
		log.Printf("Warning: error loading %s: %v", envFile, err)
	}
	cfg := &Config{
		DiscordBotToken:   os.Getenv("DISCORD_BOT_TOKEN"),
		DiscordChannelID:  os.Getenv("DISCORD_CHANNEL_ID"),
		DiscordGuildID:    os.Getenv("DISCORD_GUILD_ID"),
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"),
		BridgeUsername:    os.Getenv("BRIDGE_USERNAME"),
		BridgePassword:    os.Getenv("BRIDGE_PASSWORD"),
		DiscordPingUserID: os.Getenv("DISCORD_PING_USER_ID"),
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
	return cfg, nil
}
