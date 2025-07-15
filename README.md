# 🎵 Spotify MCP Server

A Model Context Protocol (MCP) server that enables AI assistants like Claude to interact with the Spotify Web API. This server provides secure access to Spotify features including playlist management, user profiles, and playback control.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/themuli18/spotify-mcp)

## ✨ Features

- 🎯 **MCP 2.0 Compatible** - Full JSON-RPC 2.0 support for modern AI assistants
- 🔐 **Secure Authentication** - OAuth 2.0 flow with persistent API keys
- ☁️ **Serverless Deployment** - Runs on Cloudflare Workers with Durable Objects
- 🔄 **Auto Token Refresh** - Automatic Spotify token management
- 🎵 **Rich Spotify Integration** - Playlists, profiles, playback control
- 🌐 **HTTP MCP Transport** - No WebSocket dependencies

## 🚀 Quick Start

### 1. Deploy to Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/themuli18/spotify-mcp)

Or deploy manually:

```bash
# Clone the repository
git clone https://github.com/themuli18/spotify-mcp.git
cd spotify-mcp/spotify-mcp-worker

# Install dependencies
npm install

# Configure your environment (see Configuration section)
# Then deploy
npx wrangler deploy
```

### 2. Configure Spotify App

1. Go to [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Create a new app or use an existing one
3. Add your Worker URL to redirect URIs:
   ```
   https://your-worker-name.your-subdomain.workers.dev/callback
   ```

### 3. Set Environment Variables

```bash
# Set your Spotify credentials in Cloudflare Workers
npx wrangler secret put SPOTIFY_CLIENT_ID
npx wrangler secret put SPOTIFY_CLIENT_SECRET
```

### 4. Authenticate & Get API Key

1. Visit your worker URL: `https://your-worker.workers.dev/auth`
2. Complete Spotify OAuth flow
3. Click "Generate API Key" on the success page
4. Save the API key for MCP client configuration

## 🔧 Configuration

### Cloudflare Workers Setup

1. **Install Wrangler CLI:**
   ```bash
   npm install -g wrangler
   wrangler login
   ```

2. **Configure `wrangler.toml`:**
   ```toml
   name = "spotify-mcp-worker"
   main = "dist/index.js"
   compatibility_date = "2024-01-01"
   
   [[durable_objects.bindings]]
   name = "SPOTIFY_SESSION"
   class_name = "SpotifySession"
   
   [[migrations]]
   tag = "v1"
   new_classes = ["SpotifySession"]
   ```

3. **Set Environment Variables:**
   ```bash
   npx wrangler secret put SPOTIFY_CLIENT_ID
   npx wrangler secret put SPOTIFY_CLIENT_SECRET
   ```

### MCP Client Configuration

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "spotify": {
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-http", 
        "https://your-worker.workers.dev/mcp"
      ],
      "env": {
        "AUTHORIZATION": "Bearer your-api-key-here"
      }
    }
  }
}
```

## 🛠️ Available Tools

### Playlist Management
- **`spotify:get-playlists`** - Get user's playlists
- **`spotify:create-playlist`** - Create new playlists
  ```json
  {
    "name": "My Playlist",
    "description": "Created via MCP",
    "public": false
  }
  ```

### User Information
- **`spotify:get-profile`** - Get user's Spotify profile

### Playback Control
- **`spotify:play-track`** - Start playback
  ```json
  {
    "uri": "spotify:track:4iV5W9uYEdYUVa79Axb7Rh",
    "deviceId": "optional-device-id"
  }
  ```

## 🔐 Authentication Flow

### For End Users
1. **Browser Authentication:** Visit `/auth` endpoint
2. **Spotify OAuth:** Complete authorization on Spotify
3. **API Key Generation:** Generate persistent API key
4. **MCP Configuration:** Use API key in MCP client

### For Developers
The server supports multiple authentication methods:
- **Browser Sessions:** Cookie-based for web interface
- **API Keys:** Bearer tokens for MCP clients
- **OAuth 2.1:** For advanced integrations

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │    │  Cloudflare      │    │    Spotify     │
│   (Claude)      │◄──►│  Workers         │◄──►│    Web API     │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │ Durable Objects  │
                       │ (Token Storage)  │
                       └──────────────────┘
```

### Key Components
- **Cloudflare Workers:** Serverless HTTP MCP server
- **Durable Objects:** Persistent token storage
- **Spotify Web API:** Music service integration
- **OAuth 2.0:** Secure authentication flow

## 🔍 API Endpoints

### Authentication
- `GET /auth` - Start Spotify OAuth flow
- `GET /callback` - OAuth callback handler
- `GET /generate-api-key` - Generate MCP API key
- `GET /auth-check` - Check authentication status

### MCP Protocol
- `GET /mcp` - Server information
- `POST /mcp` - JSON-RPC 2.0 requests

### OAuth 2.1 Discovery
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status

## 🧪 Development

### Local Development
```bash
# Clone and setup
git clone https://github.com/themuli18/spotify-mcp.git
cd spotify-mcp/spotify-mcp-worker

# Install dependencies
npm install

# Run locally
npx wrangler dev

# Deploy to production
npx wrangler deploy
```

### Testing
```bash
# Test MCP endpoints
curl -X POST https://your-worker.workers.dev/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-key" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Test authentication
curl https://your-worker.workers.dev/auth-check
```

## 📚 Examples

### Create a Playlist
```javascript
// Using the MCP client
const result = await mcpClient.callTool("spotify:create-playlist", {
  name: "My AI Playlist",
  description: "Created by Claude via MCP",
  public: false
});
```

### Get User Profile
```javascript
// Using the MCP client
const profile = await mcpClient.callTool("spotify:get-profile");
console.log(`Welcome, ${profile.display_name}!`);
```

## 🔒 Security

- **API Keys:** Securely stored in Durable Objects
- **Token Refresh:** Automatic Spotify token management
- **HTTPS Only:** All communications encrypted
- **No Secrets in Code:** Environment variables for credentials
- **Rate Limiting:** Respects Spotify API limits

## 📚 Learnings & Best Practices

### MCP Server Architecture

#### Durable Object Pattern
The Spotify MCP worker uses Cloudflare's Durable Objects with the `McpAgent` pattern for reliable state management:

```typescript
// Export the agent class for Durable Object binding
export class SpotifyMCP extends McpAgent<Env, Record<string, never>, Record<string, never>> {
    server = new McpServer({
        name: "Spotify MCP Server",
        version: "1.0.0",
    });

    async init() {
        // Register tools here
        this.server.tool("spotify_get_playlists", {}, async () => {
            // Tool implementation
        });
    }
}

// Export as McpAgent for wrangler.toml binding
export { SpotifyMCP as McpAgent };
```

#### Wrangler Configuration
```toml
[[durable_objects.bindings]]
name = "MCP_OBJECT"
class_name = "McpAgent"

[[migrations]]
tag = "v2"
new_sqlite_classes = ["McpAgent"]
```

### Tool Naming Convention
MCP tools must follow the pattern `^[a-zA-Z0-9_\-]{1,64}$`:

✅ **Valid tool names:**
- `spotify_get_playlists`
- `spotify_create_playlist`
- `spotify_get_profile`

❌ **Invalid tool names:**
- `spotify:get-playlists` (colons not allowed)
- `spotify-get-playlists` (hyphens in wrong position)

### Deployment Lessons

#### 1. Durable Object Migrations
- Use `new_sqlite_classes` for new Durable Objects in Wrangler 4
- Increment migration tags when making changes
- Durable Objects persist across deployments

#### 2. Module Resolution
```json
{
  "compilerOptions": {
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true
  }
}
```

#### 3. Error Handling
- MCP servers must handle connection cancellations gracefully
- Implement proper session management with `mcp-session-id`
- Log requests for debugging: `[DEBUG] Request: POST /mcp`

### Testing & Validation

#### Successful Deployment Indicators
1. **Durable Object Initialization:**
   ```
   McpAgent._init - Ok
   McpAgent.isInitialized - Ok
   McpAgent.setInitialized - Ok
   ```

2. **Active Connections:**
   ```
   Connection [id] connected to _a:[session-id]
   ```

3. **MCP Requests:**
   ```
   POST /mcp?api_key=[key] - Ok
   ```

#### Common Issues & Solutions

**Issue:** "Tool name doesn't match pattern"
- **Solution:** Remove colons, use underscores

**Issue:** "Durable Object binding failed"
- **Solution:** Ensure class is exported as `McpAgent`

**Issue:** "Module not found"
- **Solution:** Update `moduleResolution` to "bundler"

### Performance Optimization

#### Connection Management
- Multiple WebSocket connections per session
- Automatic connection cleanup
- State persistence across connections

#### Memory Management
- Durable Objects provide isolated state
- Automatic garbage collection
- Efficient token storage

### Security Considerations

#### API Key Management
- Generate unique keys per user
- Store securely in Durable Objects
- Validate on every request

#### OAuth Flow
- Secure callback handling
- Token refresh automation
- Session isolation

### Monitoring & Debugging

#### Cloudflare Workers Logs
```bash
# View real-time logs
npx wrangler tail

# Filter by specific events
npx wrangler tail --format pretty
```

#### Key Metrics to Monitor
- Connection establishment rate
- MCP request success rate
- Durable Object initialization
- Token refresh frequency

### Reference Implementation

The `math-mcp-worker` serves as a reference implementation demonstrating:
- Proper Durable Object setup
- Tool registration patterns
- Error handling
- Session management

Use it as a template for new MCP servers.

## 🚨 Troubleshooting

### Common Issues

**"Authentication required" errors:**
- Ensure you've completed the OAuth flow at `/auth`
- Generate a fresh API key if needed
- Check that the API key is correctly configured in your MCP client

**"Invalid Durable Object ID" errors:**
- This has been fixed in the latest version
- Ensure you're using the updated deployment

**Connection issues:**
- Verify your Worker URL is accessible
- Check Cloudflare Workers logs for errors
- Ensure environment variables are set correctly

### Debug Mode
Enable debug logging by checking Cloudflare Workers logs:
```bash
npx wrangler tail
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- [Spotify Web API](https://developer.spotify.com/documentation/web-api/)
- [Cloudflare Workers](https://workers.cloudflare.com/)

---

**Made with ❤️ for the MCP community**

*Need help? Open an issue or check out the [MCP documentation](https://modelcontextprotocol.io/docs)*