# Spotify MCP Cloudflare Worker

A production-ready Cloudflare Worker that provides a Model Context Protocol (MCP) server for interacting with Spotify's API. This server enables AI assistants to control Spotify playback, manage playlists, and access user data through a secure OAuth flow.

## 🚀 Features

- **🔐 MCP OAuth 2.1 Authorization** - Full OAuth 2.1 compliance with proper authorization flow
- **💾 Persistent Sessions** - Durable Objects for reliable session and token storage
- **🌐 HTTP MCP Server** - RESTful communication with AI assistants
- **🎵 Spotify API Integration** - Complete access to Spotify's Web API
- **⚡ Serverless Architecture** - Built on Cloudflare Workers for global performance
- **🛡️ Production Ready** - Secure, scalable, and maintainable

## 🛠️ Available MCP Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `spotify:get-playlists` | Retrieve user's playlists | None |
| `spotify:create-playlist` | Create a new playlist | `name`, `description?`, `public?` |
| `spotify:get-profile` | Get user profile information | None |
| `spotify:play-track` | Play a specific track | `uri`, `deviceId?` |

## 📋 Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)
- [Cloudflare account](https://dash.cloudflare.com/sign-up)
- [Spotify Developer account](https://developer.spotify.com/dashboard)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
# Navigate to the worker directory
cd spotify-mcp-worker

# Install dependencies
npm install
```

### 2. Configure Spotify App

1. **Create Spotify App:**
   - Go to [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
   - Click "Create App"
   - Fill in app details (name, description, website)

2. **Configure Redirect URIs:**
   - In your app settings, add these redirect URIs:
   ```
   https://spotify-mcp-worker.your-username.workers.dev/callback
   http://localhost:8787/callback
   ```
   - Save the changes

3. **Note Credentials:**
   - Copy your **Client ID** and **Client Secret**
   - You'll need these for the next step

### 3. Set Environment Secrets

```bash
# Set your Spotify credentials
npx wrangler secret put SPOTIFY_CLIENT_ID
# Enter your Spotify Client ID when prompted

npx wrangler secret put SPOTIFY_CLIENT_SECRET
# Enter your Spotify Client Secret when prompted
```

### 4. Deploy to Cloudflare

```bash
# Deploy the worker
npx wrangler deploy
```

### 5. Update Spotify App Settings

After deployment, update your Spotify app's redirect URI to match your actual worker URL:
```
https://spotify-mcp-worker.your-username.workers.dev/callback
```

## 🧪 Testing

### Local Development

```bash
# Start local development server
npm run dev
# or
npx wrangler dev --local
```

### Production Testing

1. **Test Authentication:**
   ```
   https://spotify-mcp-worker.your-username.workers.dev/auth
   ```

2. **Test Health Check:**
   ```
   https://spotify-mcp-worker.your-username.workers.dev/health
   ```

3. **Test Authentication Status:**
   ```
   https://spotify-mcp-worker.your-username.workers.dev/auth-check
   ```

4. **Connect MCP Client:**
   - **HTTP URL**: `https://spotify-mcp-worker.your-username.workers.dev/mcp`
   - **Transport**: HTTP (for remote MCP servers)
   - **Authentication**: Session-based via browser OAuth flow

## 🔐 Authentication Flow

1. **First-time setup:**
   - Visit `https://spotify-mcp-worker.your-username.workers.dev/auth`
   - Complete the Spotify OAuth flow
   - You'll be redirected back with a success message

2. **Using with MCP clients:**
   - Add the MCP server URL: `https://spotify-mcp-worker.your-username.workers.dev/mcp`
   - If you see authentication errors, visit the auth URL again
   - The session will persist for future requests

3. **Check authentication status:**
   - Visit `https://spotify-mcp-worker.your-username.workers.dev/auth-check`
   - This will tell you if you're currently authenticated

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | HTTP | MCP server endpoint (main interface) |
| `/auth` | GET | Spotify OAuth initiation |
| `/callback` | GET | Spotify OAuth callback handler |
| `/auth-check` | GET | Check authentication status |
| `/health` | GET | Health check endpoint |
| `/oauth/authorize` | GET | OAuth 2.1 authorization endpoint |
| `/oauth/token` | POST | OAuth 2.1 token endpoint |
| `/.well-known/oauth-protected-resource` | GET | OAuth 2.1 protected resource metadata |
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.1 authorization server metadata |

## 🔧 Configuration

### Wrangler Configuration (`