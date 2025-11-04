package main

import (
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

	// Cookie service (now handles its own refresh loop)
	cookieSvc, err := cookie.NewCookieRefreshService(cfg.BridgeUsername, cfg.BridgePassword, "kiwifarms.st")
	if err != nil {
		log.Fatalf("Failed to create cookie service: %v", err)
	}
	cookieSvc.Start()
	cookieSvc.WaitForCookie()
	if cookieSvc.GetCurrentCookie() == "" {
		log.Fatal("❌ Failed to obtain initial cookie, cannot start bridge")
	}

	// Sneedchat client
	sneedClient := sneed.NewClient(cfg.SneedchatRoomID, cookieSvc)

	// Discord bridge
	bridge, err := discord.NewBridge(cfg, sneedClient)
	if err != nil {
		log.Fatalf("Failed to create Discord bridge: %v", err)
	}
	if err := bridge.Start(); err != nil {
		log.Fatalf("Failed to start Discord bridge: %v", err)
	}
	log.Println("🌉 Discord-Sneedchat Bridge started successfully")

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