package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

	// Load configuration
	cfg, err := config.Load(envFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Parse --debug flag from CLI (overrides .env)
	debug := false
	for _, a := range os.Args {
		if a == "--debug" {
			debug = true
		}
	}
	cfg.Debug = debug

	// ---- File logging (env-driven) ------------------------------------------
	// Use LOG_FILE or BRIDGE_LOG_FILE (first non-empty wins)
	logPath := os.Getenv("LOG_FILE")
	if logPath == "" {
		logPath = os.Getenv("BRIDGE_LOG_FILE")
	}
	if logPath != "" {
		// Ensure parent dir exists
		if dir := filepath.Dir(logPath); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0o755)
		}
		f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if ferr != nil {
			log.Printf("⚠️ Failed to open log file '%s' (%v). Continuing with stdout only.", logPath, ferr)
		} else {
			// Tee logs to both stdout and file
			log.SetOutput(io.MultiWriter(os.Stdout, f))
			// microseconds for tighter timing on auth/debug traces
			log.SetFlags(log.LstdFlags | log.Lmicroseconds)
			log.Printf("📝 File logging enabled: %s", logPath)
		}
	} else {
		// keep default stdout with microseconds for consistency
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}
	// -------------------------------------------------------------------------

	log.Printf("Using .env file: %s", envFile)
	log.Printf("Using Sneedchat room ID: %d", cfg.SneedchatRoomID)
	log.Printf("Bridge username: %s", cfg.BridgeUsername)
	if cfg.Debug {
		log.Println("🪲 Debug mode enabled — full HTTP and cookie trace logging active")
	}

	// Cookie service (HTTP/1.1/2, KiwiFlare PoW, CSRF, deep debug)
	cookieSvc, err := cookie.NewCookieRefreshService(cfg.BridgeUsername, cfg.BridgePassword, "kiwifarms.st", cfg.Debug)
	if err != nil {
		log.Fatalf("Failed to create cookie service: %v", err)
	}
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

	// Auto cookie refresh every 4h (in addition to background loop inside service)
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
