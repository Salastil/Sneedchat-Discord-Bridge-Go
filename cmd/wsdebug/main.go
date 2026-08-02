// Command wsdebug is a standalone debugging tool that logs into Kiwi Farms
// using the same .env credentials as the bridge, opens the Sneedchat
// WebSocket connection, and prints/logs every raw frame received. It does
// not touch Discord at all — it exists purely to inspect what the
// WebSocket is sending.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/sneedchatbridge/config"
	"local/sneedchatbridge/cookie"
	"local/sneedchatbridge/sneed"
)

func main() {
	envFile := flag.String("env", ".env", "path to .env file")
	logFile := flag.String("log", "wsdebug.log", "path to log file")
	room := flag.Int("room", 0, "override SNEEDCHAT_ROOM_ID from .env")
	flag.Parse()

	cfg, err := config.Load(*envFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if *room != 0 {
		cfg.SneedchatRoomID = *room
	}

	f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", *logFile, err)
	}
	defer f.Close()

	logger := log.New(io.MultiWriter(os.Stdout, f), "", log.LstdFlags|log.Lmicroseconds)
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	logger.Printf("wsdebug starting — env=%s log=%s room=%d", *envFile, *logFile, cfg.SneedchatRoomID)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var dial cookie.DialContextFunc
	if cfg.TorEnabled {
		logger.Println("🧅 Starting bridge-managed Tor process...")
		torInstance, torDial, terr := cookie.StartTor(ctx)
		if terr != nil {
			log.Fatalf("Failed to start Tor: %v", terr)
		}
		defer torInstance.Close()
		dial = torDial
		logger.Println("✅ Tor process ready")
	}

	session, err := cookie.NewSessionService(ctx, cfg.KiwiScheme, cfg.KiwiHost, cfg.BridgeUsername, cfg.BridgePassword, dial, cfg.KiwiTLSInsecureSkipVerify)
	if err != nil {
		log.Fatalf("Failed to establish session: %v", err)
	}
	defer session.Close()

	client := sneed.NewClient(cfg.SneedchatRoomID, session, true, cfg.SneedchatWSURL)
	client.SetBridgeIdentity(cfg.BridgeUserID, cfg.BridgeUsername)

	client.OnRaw = func(raw string) {
		logger.Printf("RECV: %s", raw)
	}
	client.OnConnect = func() {
		logger.Printf("=== CONNECTED (room %d) ===", cfg.SneedchatRoomID)
	}
	client.OnDisconnect = func() {
		logger.Printf("=== DISCONNECTED ===")
	}
	client.OnMessage = func(m map[string]interface{}) {
		logger.Printf("MESSAGE: user=%v content=%q uuid=%v", m["username"], m["content"], m["message_uuid"])
	}
	client.OnEdit = func(uuid, content string) {
		logger.Printf("EDIT: uuid=%s content=%q", uuid, content)
	}
	client.OnDelete = func(uuid string) {
		logger.Printf("DELETE: uuid=%s", uuid)
	}

	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Initial connect failed: %v", err)
	}

	logger.Println("wsdebug running — press Ctrl+C to stop")

	<-ctx.Done()
	stopTime := time.Now().Format(time.RFC3339)
	fmt.Fprintf(f, "--- shutdown requested at %s ---\n", stopTime)
	logger.Println("Shutdown signal received, disconnecting...")
	client.Disconnect()
	logger.Println("wsdebug stopped")
}
