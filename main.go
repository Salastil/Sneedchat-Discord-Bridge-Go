package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Cookie service (HTTP/1.1, KF PoW, CSRF retry)
	cookieSvc := cookie.NewRefreshService(cfg.BridgeUsername, cfg.BridgePassword, "kiwifarms.st")
	cookieSvc.Start()
	log.Println("⏳ Waiting for initial cookie...")
	cookieSvc.WaitForCookie()
	if cookieSvc.GetCurrentCookie() == "" {
		log.Fatal("❌ Failed to obtain initial cookie, cannot start bridge")
	}

	// Sneedchat client
	sneedClient := sneed.NewClient(cfg.SneedchatRoomID, cookieSvc)

	// Discord bridge (full parity features)
	bridge, err := discord.NewBridge(cfg, sneedClient)
	if err != nil {
		log.Fatalf("Failed to create Discord bridge: %v", err)
	}
	if err := bridge.Start(); err != nil {
		log.Fatalf("Failed to start Discord bridge: %v", err)
	}
	log.Println("🌉 Discord-Sneedchat Bridge started successfully")

	// Auto cookie refresh every 4h
	go func() {
		t := time.NewTicker(4 * time.Hour)
		defer t.Stop()
		for range t.C {
			log.Println("🔄 Starting automatic cookie refresh")
			if _, err := cookieSvc.FetchFreshCookie(); err != nil {
				log.Printf("⚠️ Cookie refresh failed: %v", err)
				continue
			}
			log.Println("✅ Cookie refresh completed")
		}
	}()

	// Connect to Sneedchat
	go func() {
		if err := sneedClient.Connect(); err != nil {
			log.Printf("Initial Sneedchat connect failed: %v", err)
		}
	}()

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutdown signal received, cleaning up...")
	bridge.Stop()
	sneedClient.Disconnect()
	cookieSvc.Stop()
	log.Println("Bridge stopped successfully")
}
