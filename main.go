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
	debugFlag := false
	for i, a := range os.Args {
		if a == "--env" && i+1 < len(os.Args) {
			envFile = os.Args[i+1]
		}
		if a == "--debug" {
			debugFlag = true
		}
	}

	cfg, err := config.Load(envFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cfg.Debug = cfg.Debug || debugFlag
	log.Printf("Using .env file: %s", envFile)
	log.Printf("Using Sneedchat room ID: %d", cfg.SneedchatRoomID)
	log.Printf("Bridge username: %s", cfg.BridgeUsername)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// When cfg.TorEnabled, the bridge starts and owns its own private Tor
	// process (via a local "tor" executable) and routes the Sneedchat
	// session through it. Nothing external needs to be running. Discord and
	// media uploads use their own separate clients and are never routed
	// through Tor.
	var dial cookie.DialContextFunc
	if cfg.TorEnabled {
		log.Println("🧅 Starting bridge-managed Tor process...")
		torInstance, torDial, err := cookie.StartTor(ctx)
		if err != nil {
			log.Fatalf("❌ Failed to start Tor: %v", err)
		}
		defer torInstance.Close()
		dial = torDial
		log.Println("✅ Tor process ready")
	}

	// SessionService owns the TLS config, cookie store, and shared transport.
	// Login is performed here; cookies are stored as plain strings, no jar.
	session, err := cookie.NewSessionService(ctx, cfg.KiwiScheme, cfg.KiwiHost, cfg.BridgeUsername, cfg.BridgePassword, dial, cfg.KiwiTLSInsecureSkipVerify)
	if err != nil {
		log.Fatalf("❌ Failed to establish session: %v", err)
	}

	// NewClient uses session.Transport() for the WebSocket dialer,
	// mirroring sockchat's NewSocket pattern exactly.
	sneedClient := sneed.NewClient(cfg.SneedchatRoomID, session, cfg.Debug, cfg.SneedchatWSURL)
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
	session.Close()
	log.Println("Bridge stopped successfully")
}
