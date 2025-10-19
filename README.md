# Sneedchat-Discord Bridge

A high-performance bridge written in Go that synchronizes messages between Kiwi Farms Sneedchat and Discord, with full support for edits, deletes, embeds, attachments, and BBCode parsing.

## Features

- ✅ Bidirectional message sync (Sneedchat ↔ Discord)
- ✅ Edit and delete synchronization
- ✅ Attachment uploads and BBcode formating via Litterbox
- ✅ BBCode → Markdown parsing
- ✅ Message queueing during outages

## Performance

**Typical resource usage:**
- **CPU**: Efficient, easily handled by a Raspberry Pi, a few % on cpu usage at heavy load. 
- **Memory**: 50-70 MB at full load in a busy channel
- **Network**: Minimal (< 1 MB/minute) except when uploading attachments

## Requirements

- **Go 1.19 or higher**
- **Discord Bot Token** with proper permissions
- **Discord Webhook URL**
- **Kiwi Farms account** with Sneedchat access

## Installation

### 1. Install Go (Debian)

```bash
# Install Go from package manager
sudo apt update
sudo apt install golang git

# Verify installation
go version  # Should show 1.19 or higher
```

### 2. Clone and Build

```bash
# Create installation directory
cd /opt/sneedchat-bridge

# Clone repository 
git clone [repository url].git

# Initialize Go module
go mod init sneedchat-discord-bridge

# Download dependencies
go mod tidy

# Build the binary
go build -o sneedchat-bridge

Launch using ./sneedchat-bridge --env .env
```
## Discord Setup

### Step 1: Create Discord Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **"New Application"**
3. Name it (e.g., "Sneedchat Bridge")
4. Click **"Create"**

### Step 2: Create Bot

1. In your application, go to **"Bot"** tab (left sidebar)
2. Click **"Add Bot"** → **"Yes, do it!"**
3. Under **"TOKEN"**, click **"Reset Token"** → **"Copy"**
   - ⚠️ **Save this token** - you'll need it for `DISCORD_BOT_TOKEN`
4. Scroll down to **"Privileged Gateway Intents"**:
   - ✅ Enable **"MESSAGE CONTENT INTENT"**
   - ✅ Enable **"SERVER MEMBERS INTENT"** (optional)
   - Click **"Save Changes"**

### Step 3: Invite Bot to Server

1. Go to **"OAuth2"** → **"URL Generator"** tab
2. Select **SCOPES**:
   - ✅ `bot`
   - ✅ `applications.commands` (optional)
3. Select **BOT PERMISSIONS**:
   - ✅ `Read Messages/View Channels`
   - ✅ `Send Messages`
   - ✅ `Manage Messages` (for edits/deletes)
   - ✅ `Embed Links`
   - ✅ `Attach Files`
   - ✅ `Read Message History`
   - ✅ `Add Reactions` (optional)
4. Copy the generated URL at bottom
5. Open URL in browser and select your server
6. Click **"Authorize"**

### Step 4: Create Webhook

1. In Discord, go to your server
2. Right-click the **channel** you want to bridge
3. Click **"Edit Channel"**
4. Go to **"Integrations"** tab
5. Click **"Webhooks"** → **"New Webhook"**
6. Name it (e.g., "Sneedchat")
7. Set avatar (optional)
8. Click **"Copy Webhook URL"**
   - ⚠️ **Save this URL** - you'll need it for `DISCORD_WEBHOOK_URL`

### Step 5: Get Channel and Guild IDs

1. Enable **Developer Mode** in Discord:
   - User Settings → Advanced → Developer Mode (toggle ON)
2. **Channel ID**:
   - Right-click the bridge channel → "Copy Channel ID"
3. **Guild ID** (Server ID):
   - Right-click server name → "Copy Server ID"

---

## Configuration

### Create Environment File

```bash
cd /opt/sneedchat-bridge
mv .env.example .env

```
### To run multiple bridges (different rooms/channels):
Copy binary and create separate .env files, example .env.general, .env.keno-kasino and change the room integer found under `SNEEDCHAT_ROOM_ID=16`
Create separate systemd services with unique names


**Important Notes:**
- Replace `BRIDGE_USERNAME` with your **Kiwi Farms username** (not email)
- `SNEEDCHAT_ROOM_ID=1` is the default Sneedchat room
- Keep quotes out of values
- Don't share your `.env` file!

---

Fill in your values:

```env
# Discord Configuration
DISCORD_BOT_TOKEN=YOUR_BOT_TOKEN_HERE
DISCORD_CHANNEL_ID=1234567890123456789
DISCORD_GUILD_ID=9876543210987654321
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz

# Sneedchat Configuration
SNEEDCHAT_ROOM_ID=1
BRIDGE_USERNAME=YourKiwiUsername
BRIDGE_PASSWORD=YourKiwiPassword

# Optional: Bridge user filtering (Used to prevent your messages echoing back to Discord and for queued messages during outages)
# Get your Kiwi user ID from profile URL
BRIDGE_USER_ID=12345

# Optional: Discord ping conversion
# Your Discord user ID (right-click yourself → Copy User ID)
DISCORD_PING_USER_ID=1234567890123456789

# Optional: Enable file logging
ENABLE_FILE_LOGGING=false
```

### Set Permissions

```bash
# Secure the config file
sudo chmod 600 .env
sudo chown root:root .env

# Set binary permissions
sudo chmod 755 sneedchat-bridge
```

Watch for:
```
✅ Successfully fetched fresh cookie with xf_user
✅ Successfully connected to Sneedchat room 1
🤖 Discord bot ready: Sneedchat Bridge
🌉 Discord-Sneedchat Bridge started successfully
```

Press `Ctrl+C` to terminate bridge.


## Systemd Service Setup:
---
### Create Service File

```bash
sudo nano /etc/systemd/system/sneedchat-bridge.service
```

Paste this configuration:

```ini
[Unit]
Description=Sneedchat-Discord Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sneedchat-bridge
ExecStart=/opt/sneedchat-bridge/sneedchat-bridge --env /opt/sneedchat-bridge/.env
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening (optional)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable sneedchat-bridge

# Start service now
sudo systemctl start sneedchat-bridge

# Check status
sudo systemctl status sneedchat-bridge
```

---

## Troubleshooting

### Cookie Issues

If you see `xf_user cookie missing` in stdout:

1. **Verify credentials** - Try logging in manually on Kiwi Farms
2. **Check rate limits** - KiwiFlare might be blocking you temporarily or is suffering DDOS attacks
3. The bridge will **retry indefinitely** to acquire login cookie with exponential backoff in event of Kiwifarms outages. 

### Discord Permission Issues

If messages aren't appearing:
1. Check bot has **Read Messages** and **Send Messages** in channel
2. Verify webhook is for the correct channel
3. Check channel isn't restricted to certain roles


## Security Notes

- 🔐 Keep `.env` file secure (chmod 600)
- 🔐 Rotate Discord bot token or Kiwifarms password if leaked

## License

This bridge is provided as-is. Use responsibly and in accordance with Kiwi Farms and Discord Terms of Service.

## Credits

Built with:
- [discordgo](https://github.com/bwmarrin/discordgo) - Discord API
- [gorilla/websocket](https://github.com/gorilla/websocket) - WebSocket client
- [godotenv](https://github.com/joho/godotenv) - Environment loading