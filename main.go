package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"local/sneedchatbridge/config"
	"local/sneedchatbridge/cookie"
	"local/sneedchatbridge/discord"
	"local/sneedchatbridge/sneed"
)

func main() {
	envFile := ".env"
	for i, a := range os.Args {
		if a == "--env" && i+1 < len(os.Args) {
			envFile = os.Args[i+1]
		}
	}

	cfg, err := config.Load(envFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Using .env file: %s", envFile)
	log.Printf("Using Sneedchat room ID: %d", cfg.SneedchatRoomID)
	log.Printf("Bridge username: %s", cfg.BridgeUsername)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// SessionService owns the TLS config, cookie store, and shared transport.
	// Login is performed here; cookies are stored as plain strings, no jar.
	session, err := cookie.NewSessionService(ctx, "kiwifarms.st", cfg.BridgeUsername, cfg.BridgePassword)
	if err != nil {
		log.Fatalf("❌ Failed to establish session: %v", err)
	}

	// NewClient uses session.Transport() for the WebSocket dialer,
	// mirroring sockchat's NewSocket pattern exactly.
	sneedClient := sneed.NewClient(cfg.SneedchatRoomID, session, cfg.Debug)
	sneedClient.SetBridgeIdentity(cfg.BridgeUserID, cfg.BridgeUsername)

	bridge, err := discord.NewBridge(cfg, sneedClient)
	if err != nil {
		log.Fatalf("Failed to create Discord bridge: %v", err)
	}
	if err := bridge.Start(); err != nil {
		log.Fatalf("Failed to start Discord bridge: %v", err)
	}
	log.Println("🌉 Discord-Sneedchat Bridge started successfully")

	go func() {
		if err := sneedClient.Connect(ctx); err != nil {
			log.Printf("Initial Sneedchat connect failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutdown signal received, cleaning up...")
	bridge.Stop()
	sneedClient.Disconnect()
	log.Println("Bridge stopped successfully")
}
