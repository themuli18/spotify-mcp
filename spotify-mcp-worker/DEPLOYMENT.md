# Deployment Guide

## ✅ Completed Tasks

1. **Created Cloudflare Worker Project Structure**
   - Set up `wrangler.toml` with Durable Objects configuration
   - Created TypeScript configuration
   - Installed necessary dependencies

2. **Implemented Durable Objects for Session Management**
   - Created `SpotifySession` class for token storage
   - Implemented token refresh logic
   - Added proper fetch handler for Durable Object communication

3. **Refactored Authentication Flow**
   - Adapted `SpotifyAuth` class for Cloudflare Workers
   - Implemented `/login` and `/callback` routes
   - Added session cookie management

4. **Implemented MCP WebSocket Server**
   - Created custom MCP server for Cloudflare Workers
   - Added tools for playlists, profile, and playback
   - Implemented proper WebSocket upgrade handling

## 🚀 Next Steps for Deployment

### 1. Set Up Spotify App
1. Go to [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Create a new app or use existing one
3. Add redirect URI: `https://spotify-mcp-worker.your-username.workers.dev/callback`
4. Note your Client ID and Client Secret

### 2. Set Secrets
```bash
cd spotify-mcp-worker
npx wrangler secret put SPOTIFY_CLIENT_ID
# Enter your Spotify Client ID when prompted

npx wrangler secret put SPOTIFY_CLIENT_SECRET
# Enter your Spotify Client Secret when prompted
```

### 3. Deploy to Cloudflare
```bash
npx wrangler deploy
```

### 4. Update Spotify App Settings
After deployment, update your Spotify app's redirect URI to match your actual worker URL.

### 5. Test the Deployment
1. Visit `https://spotify-mcp-worker.your-username.workers.dev/login`
2. Complete OAuth flow
3. Use WebSocket URL: `wss://spotify-mcp-worker.your-username.workers.dev/mcp`

## 🔧 Available Endpoints

- `GET /login` - Initiate Spotify OAuth
- `GET /callback` - Handle OAuth callback
- `GET /health` - Health check
- `WS /mcp` - MCP WebSocket endpoint

## 🛠️ Available MCP Tools

- `spotify:get-playlists` - Get user's playlists
- `spotify:create-playlist` - Create new playlist
- `spotify:get-profile` - Get user profile
- `spotify:play-track` - Play a track

## 📝 Notes

- The worker uses Durable Objects for persistent session storage
- Tokens are automatically refreshed when needed
- Sessions are identified by cookies
- All communication with Spotify API is done server-side 