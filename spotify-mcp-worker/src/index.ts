import { SpotifyAuth, SpotifySession, Env } from './session';
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Define our MCP agent with Spotify tools
export class SpotifyMCP extends McpAgent<Env, Record<string, never>, Record<string, never>> {
    server = new McpServer({
        name: "Spotify MCP Server",
        version: "1.0.0",
    });

    async init() {
        // Get playlists tool
        this.server.tool(
            "spotify_get_playlists",
            {},
            async () => {
                const sessionStub = await this.getSessionStub();
                const accessToken = await this.getValidAccessToken(sessionStub);
                if (!accessToken) {
                    return {
                        content: [{ type: "text", text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." }]
                    };
                }
                const response = await fetch("https://api.spotify.com/v1/me/playlists", {
                    headers: { "Authorization": `Bearer ${accessToken}` }
                });
                if (!response.ok) {
                    throw new Error(`Failed to get playlists: ${response.statusText}`);
                }
                const data = await response.json();
                return {
                    content: [{ type: "text", text: JSON.stringify(data, null, 2) }]
                };
            }
        );

        // Create playlist tool
        this.server.tool(
            "spotify_create_playlist",
            {
                name: z.string().describe("Name of the playlist"),
                description: z.string().optional().describe("Description of the playlist"),
                public: z.boolean().optional().describe("Whether the playlist should be public")
            },
            async ({ name, description, public: isPublic }) => {
                const sessionStub = await this.getSessionStub();
                const accessToken = await this.getValidAccessToken(sessionStub);
                if (!accessToken) {
                    return {
                        content: [{ type: "text", text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." }]
                    };
                }
                const userResponse = await fetch("https://api.spotify.com/v1/me", {
                    headers: { "Authorization": `Bearer ${accessToken}` }
                });
                if (!userResponse.ok) {
                    throw new Error(`Failed to get user profile: ${userResponse.statusText}`);
                }
                const user = await userResponse.json() as { id: string };
                const response = await fetch(`https://api.spotify.com/v1/users/${user.id}/playlists`, {
                    method: "POST",
                    headers: {
                        "Authorization": `Bearer ${accessToken}`,
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        name,
                        description,
                        public: isPublic ?? false
                    })
                });
                if (!response.ok) {
                    throw new Error(`Failed to create playlist: ${response.statusText}`);
                }
                const playlist = await response.json();
                return {
                    content: [{ type: "text", text: JSON.stringify(playlist, null, 2) }]
                };
            }
        );

        // Get profile tool
        this.server.tool(
            "spotify_get_profile",
            {},
            async () => {
                const sessionStub = await this.getSessionStub();
                const accessToken = await this.getValidAccessToken(sessionStub);
                if (!accessToken) {
                    return {
                        content: [{ type: "text", text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." }]
                    };
                }
                const response = await fetch("https://api.spotify.com/v1/me", {
                    headers: { "Authorization": `Bearer ${accessToken}` }
                });
                if (!response.ok) {
                    throw new Error(`Failed to get profile: ${response.statusText}`);
                }
                const profile = await response.json();
                return {
                    content: [{ type: "text", text: JSON.stringify(profile, null, 2) }]
                };
            }
        );

        // Play track tool
        this.server.tool(
            "spotify_play_track",
            {
                uri: z.string().describe("Spotify URI of the track to play"),
                deviceId: z.string().optional().describe("Optional device ID to play on")
            },
            async ({ uri, deviceId }) => {
                const sessionStub = await this.getSessionStub();
                const accessToken = await this.getValidAccessToken(sessionStub);
                if (!accessToken) {
                    return {
                        content: [{ type: "text", text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." }]
                    };
                }
                const endpoint = deviceId ?
                    `https://api.spotify.com/v1/me/player/play?device_id=${deviceId}` :
                    'https://api.spotify.com/v1/me/player/play';
                const response = await fetch(endpoint, {
                    method: "PUT",
                    headers: {
                        "Authorization": `Bearer ${accessToken}`,
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        uris: [uri]
                    })
                });
                if (!response.ok) {
                    throw new Error(`Failed to start playback: ${response.statusText}`);
                }
                return {
                    content: [{ type: "text", text: "Playback started successfully" }]
                };
            }
        );

        // Search tool
        this.server.tool(
            "spotify_search",
            {
                query: z.string().describe("Search query"),
                type: z.enum(["track", "artist", "album", "playlist"]).optional().describe("Type of search (default: track)"),
                limit: z.number().optional().describe("Maximum number of results (default: 10)")
            },
            async ({ query, type = "track", limit = 10 }) => {
                const sessionStub = await this.getSessionStub();
                const accessToken = await this.getValidAccessToken(sessionStub);
                if (!accessToken) {
                    return {
                        content: [{ type: "text", text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." }]
                    };
                }
                const params = new URLSearchParams({
                    q: query,
                    type,
                    limit: String(limit)
                });
                const response = await fetch(`https://api.spotify.com/v1/search?${params.toString()}`, {
                    headers: { "Authorization": `Bearer ${accessToken}` }
                });
                if (!response.ok) {
                    throw new Error(`Failed to search: ${response.statusText}`);
                }
                const data = await response.json();
                return {
                    content: [{ type: "text", text: JSON.stringify(data, null, 2) }]
                };
            }
        );
    }

    // Session and token helpers
    private async getSessionStub(): Promise<DurableObjectStub | null> {
        // For MCP requests, we need to get the session from the request context
        // This will be called from the main fetch handler
        return null;
    }

    private async getValidAccessToken(sessionStub: DurableObjectStub | null): Promise<string | null> {
        if (!sessionStub) return null;
        
        const response = await sessionStub.fetch(new Request('http://localhost/getValidAccessToken'));
        if (response.ok) {
            const data = await response.json() as { token: string | null };
            return data.token;
        }
        return null;
    }
}

// Export the classes for Durable Object binding
export { SpotifyMCP as McpAgent };
export { SpotifySession };

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const url = new URL(request.url);
        const auth = new SpotifyAuth(env);
        
        // Debug logging
        console.log(`[DEBUG] Request: ${request.method} ${url.pathname}${url.search}`);
        console.log(`[DEBUG] Headers:`, Object.fromEntries(request.headers.entries()));

        // Route for initiating login (legacy)
        if (url.pathname === "/login") {
            console.log(`[DEBUG] Legacy login request`);
            const host = url.hostname;
            const { url: authUrl, state } = auth.generateAuthUrl(host);
            return Response.redirect(authUrl, 302);
        }

        // Simple auth endpoint for MCP clients
        if (url.pathname === "/auth") {
            console.log(`[DEBUG] Auth endpoint request`);
            const host = url.hostname;
            const { url: authUrl, state } = auth.generateAuthUrl(host);
            
            // If it's a browser request, redirect to Spotify
            const userAgent = request.headers.get('User-Agent') || '';
            if (userAgent.includes('Mozilla') || userAgent.includes('Chrome') || userAgent.includes('Safari')) {
                return Response.redirect(authUrl, 302);
            }
            
            // For API requests, return the auth URL
            return new Response(JSON.stringify({
                message: "Authentication required",
                auth_url: authUrl,
                instructions: "Visit the auth_url in your browser to authenticate with Spotify"
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // OAuth 2.1 Authorization endpoint
        if (url.pathname === "/oauth/authorize") {
            console.log(`[DEBUG] OAuth authorize request`);
            
            const clientId = url.searchParams.get("client_id");
            const responseType = url.searchParams.get("response_type");
            const redirectUri = url.searchParams.get("redirect_uri");
            const scope = url.searchParams.get("scope");
            const state = url.searchParams.get("state");
            const codeChallenge = url.searchParams.get("code_challenge");
            const codeChallengeMethod = url.searchParams.get("code_challenge_method");
            const resource = url.searchParams.get("resource");

            console.log(`[DEBUG] OAuth params:`, {
                clientId,
                responseType,
                redirectUri,
                scope,
                state,
                codeChallenge: codeChallenge ? 'present' : 'missing',
                codeChallengeMethod,
                resource
            });

            if (responseType !== "code" || !clientId || !redirectUri || !state || !codeChallenge) {
                console.log(`[DEBUG] Invalid authorization request - missing required params`);
                return new Response("Invalid authorization request", { status: 400 });
            }

            // Store the OAuth parameters for later use
            const authParams = {
                clientId,
                redirectUri,
                scope,
                state,
                codeChallenge,
                codeChallengeMethod,
                resource
            };

            console.log(`[DEBUG] Auth params stored:`, authParams);

            // Generate a temporary storage key for this authorization request
            const authKey = crypto.randomUUID();
            
            // For now, we'll use a simple approach: redirect to Spotify OAuth
            // and store the parameters in the URL state
            const spotifyAuthUrl = auth.generateAuthUrl(url.hostname);
            const combinedState = `${state}:${authKey}:${encodeURIComponent(JSON.stringify(authParams))}`;
            
            console.log(`[DEBUG] Generated combined state:`, combinedState);
            
            const spotifyUrl = new URL(spotifyAuthUrl.url);
            spotifyUrl.searchParams.set('state', combinedState);
            
            console.log(`[DEBUG] Redirecting to Spotify:`, spotifyUrl.toString());
            
            return Response.redirect(spotifyUrl.toString(), 302);
        }

        // OAuth 2.1 Token endpoint
        if (url.pathname === "/oauth/token") {
            if (request.method !== "POST") {
                return new Response("Method not allowed", { status: 405 });
            }

            try {
                const body = await request.formData();
                const grantType = body.get("grant_type");
                const code = body.get("code");
                const redirectUri = body.get("redirect_uri");
                const clientId = body.get("client_id");
                const codeVerifier = body.get("code_verifier");
                const resource = body.get("resource");

                if (grantType === "authorization_code" && code && codeVerifier) {
                    // Exchange authorization code for access token
                    // For now, we'll create a simple token format
                    // In production, you'd validate the authorization code and code_verifier
                    const sessionId = crypto.randomUUID();
                    const accessToken = `${sessionId}:spotify_token_placeholder`;
                    
                    return new Response(JSON.stringify({
                        access_token: accessToken,
                        token_type: "Bearer",
                        expires_in: 3600,
                        scope: "user-library-read playlist-read-private playlist-modify-public playlist-modify-private"
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                return new Response("Invalid token request", { status: 400 });
            } catch (error) {
                return new Response("Token request failed", { status: 500 });
            }
        }

        // Route for the Spotify callback (handles both direct OAuth and OAuth 2.1 flows)
        if (url.pathname === "/callback") {
            console.log(`[DEBUG] Spotify callback received`);
            
            const code = url.searchParams.get("code");
            const state = url.searchParams.get("state");

            console.log(`[DEBUG] Callback params:`, { code: code ? 'present' : 'missing', state });

            if (!code || !state) {
                console.log(`[DEBUG] Invalid callback parameters`);
                return new Response("Invalid callback parameters", { status: 400 });
            }

            try {
                const host = url.hostname;
                
                // Check if this is an OAuth 2.1 flow (state contains multiple parts)
                if (state.includes(':')) {
                    console.log(`[DEBUG] Processing OAuth 2.1 flow`);
                    
                    const [originalState, authKey, encodedParams] = state.split(':');
                    const authParams = JSON.parse(decodeURIComponent(encodedParams));
                    
                    console.log(`[DEBUG] Parsed auth params:`, authParams);
                    
                    // Get Spotify tokens
                    const tokens = await auth.getAccessToken(code, originalState, host);
                    console.log(`[DEBUG] Got Spotify tokens:`, { access_token: tokens.access_token ? 'present' : 'missing' });
                    
                    const doId = env.SPOTIFY_SESSION.newUniqueId();
                    const stub = env.SPOTIFY_SESSION.get(doId);
                    
                    await stub.fetch(new Request('http://localhost/setTokens', {
                        method: 'POST',
                        body: JSON.stringify(tokens)
                    }));
                    console.log(`[DEBUG] Stored tokens in session:`, doId.toString());

                    // Generate authorization code for OAuth 2.1
                    const authCode = crypto.randomUUID();
                    console.log(`[DEBUG] Generated auth code:`, authCode);
                    
                    // Redirect back to the original redirect URI with the authorization code
                    const redirectUrl = new URL(authParams.redirectUri);
                    redirectUrl.searchParams.set('code', authCode);
                    redirectUrl.searchParams.set('state', originalState);
                    
                    console.log(`[DEBUG] Redirecting to:`, redirectUrl.toString());
                    
                    return Response.redirect(redirectUrl.toString(), 302);
                } else {
                    // Legacy direct OAuth flow
                    const tokens = await auth.getAccessToken(code, state, host);
                    const doId = env.SPOTIFY_SESSION.newUniqueId();
                    const stub = env.SPOTIFY_SESSION.get(doId);
                    
                    await stub.fetch(new Request('http://localhost/setTokens', {
                        method: 'POST',
                        body: JSON.stringify(tokens)
                    }));

                    const response = new Response(`
                        <html>
                            <head><title>Spotify MCP - Authentication Success</title></head>
                            <body>
                                <h1>Success! You are authenticated with Spotify.</h1>
                                <p>You can now use the MCP tools.</p>
                                <h2>For MCP Clients (like Claude):</h2>
                                <p>Generate an API key for persistent authentication:</p>
                                <button onclick="generateApiKey()">Generate API Key</button>
                                <div id="apiKeyResult" style="margin-top: 10px; padding: 10px; background: #f0f0f0; display: none;">
                                    <strong>Your API Key:</strong>
                                    <pre id="apiKeyText"></pre>
                                    <h4>Usage Options:</h4>
                                    <p><strong>Option 1: URL Parameter (Recommended)</strong></p>
                                    <pre id="urlParam" style="background: #e0e0e0; padding: 5px; font-size: 12px;"></pre>
                                    <p><strong>Option 2: Authorization Header</strong></p>
                                    <pre id="authHeader" style="background: #e0e0e0; padding: 5px; font-size: 12px;"></pre>
                                </div>
                                <script>
                                    async function generateApiKey() {
                                        try {
                                            const response = await fetch('/generate-api-key');
                                            const data = await response.json();
                                            if (data.api_key) {
                                                const apiKey = data.api_key;
                                                document.getElementById('apiKeyText').textContent = apiKey;
                                                document.getElementById('urlParam').textContent = 'https://spotify-mcp-worker.aike-357.workers.dev/mcp?api_key=' + apiKey;
                                                document.getElementById('authHeader').textContent = 'Authorization: Bearer ' + apiKey;
                                                document.getElementById('apiKeyResult').style.display = 'block';
                                            } else {
                                                alert('Error: ' + data.error);
                                            }
                                        } catch (error) {
                                            alert('Error generating API key: ' + error);
                                        }
                                    }
                                </script>
                                <p><small>You can close this window after generating your API key.</small></p>
                            </body>
                        </html>
                    `, { 
                        status: 200,
                        headers: { 'Content-Type': 'text/html' }
                    });
                    response.headers.set("Set-Cookie", `session_id=${doId.toString()}; HttpOnly; Secure; Path=/; SameSite=Strict`);
                    return response;
                }
            } catch (error) {
                return new Response(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`, { status: 500 });
            }
        }

        // MCP endpoints
        if (url.pathname === "/sse" || url.pathname === "/sse/message") {
            return SpotifyMCP.serveSSE("/sse").fetch(request, env, ctx);
        }
        if (url.pathname === "/mcp") {
            return SpotifyMCP.serve("/mcp").fetch(request, env, ctx);
        }

        // OAuth 2.1 Protected Resource Metadata endpoint
        if (url.pathname === "/.well-known/oauth-protected-resource") {
            return new Response(JSON.stringify({
                resource: "https://spotify-mcp-worker.aike-357.workers.dev/mcp",
                authorization_servers: [
                    "https://spotify-mcp-worker.aike-357.workers.dev/.well-known/oauth-authorization-server"
                ],
                jwks_uri: "https://spotify-mcp-worker.aike-357.workers.dev/.well-known/jwks.json",
                token_introspection_endpoint: "https://spotify-mcp-worker.aike-357.workers.dev/oauth/introspect"
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // OAuth 2.1 Authorization Server Metadata endpoint
        if (url.pathname === "/.well-known/oauth-authorization-server") {
            return new Response(JSON.stringify({
                issuer: "https://spotify-mcp-worker.aike-357.workers.dev",
                authorization_endpoint: "https://spotify-mcp-worker.aike-357.workers.dev/oauth/authorize",
                token_endpoint: "https://spotify-mcp-worker.aike-357.workers.dev/oauth/token",
                registration_endpoint: "https://spotify-mcp-worker.aike-357.workers.dev/oauth/register",
                scopes_supported: ["user-library-read", "playlist-read-private", "playlist-modify-public", "playlist-modify-private"],
                response_types_supported: ["code"],
                grant_types_supported: ["authorization_code", "refresh_token"],
                token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
                code_challenge_methods_supported: ["S256"],
                resource_parameter_supported: true
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Web interface for hosted Claude
        if (url.pathname === "/web" || url.pathname === "/") {
            return new Response(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Spotify MCP Web Interface</title>
                    <style>
                        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                        .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                        button { background: #1db954; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
                        button:hover { background: #1ed760; }
                        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; max-height: 400px; overflow-y: auto; }
                        input, textarea { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 3px; }
                        .auth-notice { background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }
                    </style>
                </head>
                <body>
                    <h1>🎵 Spotify MCP Web Interface</h1>
                    <p>This interface allows Claude (hosted version) to interact with your Spotify account.</p>
                    
                    <div class="auth-notice">
                        <strong>Authentication Required:</strong> You need to authenticate with Spotify first.
                        <button onclick="authenticate()">Authenticate with Spotify</button>
                    </div>
                    
                    <div class="section">
                        <h2>🎵 Get Your Playlists</h2>
                        <button onclick="getPlaylists()">Get My Playlists</button>
                        <div id="playlists-result" class="result" style="display: none;"></div>
                    </div>
                    
                    <div class="section">
                        <h2>👤 Get Your Profile</h2>
                        <button onclick="getProfile()">Get My Profile</button>
                        <div id="profile-result" class="result" style="display: none;"></div>
                    </div>
                    
                    <div class="section">
                        <h2>➕ Create Playlist</h2>
                        <input type="text" id="playlist-name" placeholder="Playlist Name" required>
                        <textarea id="playlist-description" placeholder="Playlist Description (optional)"></textarea>
                        <label><input type="checkbox" id="playlist-public"> Make playlist public</label><br>
                        <button onclick="createPlaylist()">Create Playlist</button>
                        <div id="create-result" class="result" style="display: none;"></div>
                    </div>
                    
                    <div class="section">
                        <h2>▶️ Play Track</h2>
                        <input type="text" id="track-uri" placeholder="Spotify Track URI (e.g., spotify:track:4iV5W9uYEdYUVa79Axb7Rh)">
                        <input type="text" id="device-id" placeholder="Device ID (optional)">
                        <button onclick="playTrack()">Play Track</button>
                        <div id="play-result" class="result" style="display: none;"></div>
                    </div>
                    
                    <script>
                        const API_BASE = window.location.origin;
                        
                        function authenticate() {
                            window.location.href = API_BASE + '/auth';
                        }
                        
                        async function makeRequest(endpoint, method = 'GET', body = null) {
                            try {
                                const response = await fetch(API_BASE + endpoint, {
                                    method,
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: body ? JSON.stringify(body) : null
                                });
                                return await response.json();
                            } catch (error) {
                                return { error: error.message };
                            }
                        }
                        
                        async function getPlaylists() {
                            const result = await makeRequest('/api/playlists');
                            document.getElementById('playlists-result').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                            document.getElementById('playlists-result').style.display = 'block';
                        }
                        
                        async function getProfile() {
                            const result = await makeRequest('/api/profile');
                            document.getElementById('profile-result').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                            document.getElementById('profile-result').style.display = 'block';
                        }
                        
                        async function createPlaylist() {
                            const name = document.getElementById('playlist-name').value;
                            const description = document.getElementById('playlist-description').value;
                            const isPublic = document.getElementById('playlist-public').checked;
                            
                            if (!name) {
                                alert('Please enter a playlist name');
                                return;
                            }
                            
                            const result = await makeRequest('/api/playlists', 'POST', {
                                name,
                                description,
                                public: isPublic
                            });
                            
                            document.getElementById('create-result').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                            document.getElementById('create-result').style.display = 'block';
                        }
                        
                        async function playTrack() {
                            const uri = document.getElementById('track-uri').value;
                            const deviceId = document.getElementById('device-id').value;
                            
                            if (!uri) {
                                alert('Please enter a track URI');
                                return;
                            }
                            
                            const result = await makeRequest('/api/play', 'POST', {
                                uri,
                                deviceId: deviceId || undefined
                            });
                            
                            document.getElementById('play-result').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                            document.getElementById('play-result').style.display = 'block';
                        }
                    </script>
                </body>
                </html>
            `, {
                headers: { 'Content-Type': 'text/html' }
            });
        }

        // REST API endpoints for the web interface
        if (url.pathname === "/api/playlists") {
            const sessionStub = await getSessionFromCookie(request, env);
            if (!sessionStub) {
                return new Response(JSON.stringify({
                    error: "Authentication required. Please visit /auth to authenticate with Spotify."
                }), { 
                    status: 401,
                    headers: { 'Content-Type': 'application/json' } 
                });
            }
            
            if (request.method === "GET") {
                return await handleGetPlaylists(sessionStub);
            } else if (request.method === "POST") {
                const body = await request.json();
                return await handleCreatePlaylist(sessionStub, body);
            }
        }

        if (url.pathname === "/api/profile") {
            const sessionStub = await getSessionFromCookie(request, env);
            if (!sessionStub) {
                return new Response(JSON.stringify({
                    error: "Authentication required. Please visit /auth to authenticate with Spotify."
                }), { 
                    status: 401,
                    headers: { 'Content-Type': 'application/json' } 
                });
            }
            return await handleGetProfile(sessionStub);
        }

        if (url.pathname === "/api/play") {
            const sessionStub = await getSessionFromCookie(request, env);
            if (!sessionStub) {
                return new Response(JSON.stringify({
                    error: "Authentication required. Please visit /auth to authenticate with Spotify."
                }), { 
                    status: 401,
                    headers: { 'Content-Type': 'application/json' } 
                });
            }
            const body = await request.json();
            return await handlePlayTrack(sessionStub, body);
        }

        // Health check endpoint
        if (url.pathname === "/health") {
            return new Response("OK", { status: 200 });
        }

        // Clear session endpoint (for debugging)
        if (url.pathname === "/clear-session") {
            console.log(`[DEBUG] Clear session request`);
            
            const apiKey = url.searchParams.get("api_key");
            if (apiKey && isValidUUID(apiKey)) {
                const sessionStub = await findSessionByApiKey(apiKey, env);
                if (sessionStub) {
                    // Clear the session by setting empty tokens
                    await sessionStub.fetch(new Request('http://localhost/setTokens', {
                        method: 'POST',
                        body: JSON.stringify({})
                    }));
                    
                    return new Response(JSON.stringify({
                        success: true,
                        message: "Session cleared successfully. Please re-authenticate with Spotify."
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            }
            
            return new Response(JSON.stringify({
                success: false,
                message: "Invalid API key or session not found"
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Status endpoint for MCP clients
        if (url.pathname === "/status") {
            const cookie = request.headers.get("Cookie");
            const sessionId = cookie?.match(/session_id=([a-f0-9-]+)/)?.[1];
            
            if (sessionId) {
                const doId = env.SPOTIFY_SESSION.idFromString(sessionId);
                const sessionStub = env.SPOTIFY_SESSION.get(doId);
                const validToken = await getValidAccessToken(sessionStub);
                
                return new Response(JSON.stringify({
                    authenticated: !!validToken,
                    session_id: sessionId,
                    message: validToken ? "Authenticated with Spotify" : "Session exists but no valid token"
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } else {
                return new Response(JSON.stringify({
                    authenticated: false,
                    message: "No session found",
                    auth_url: "https://spotify-mcp-worker.aike-357.workers.dev/auth"
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }

        // API key generation endpoint for MCP clients
        if (url.pathname === "/generate-api-key") {
            console.log(`[DEBUG] API key generation request`);
            
            try {
                const cookie = request.headers.get("Cookie");
                console.log(`[DEBUG] Cookie header:`, cookie ? 'present' : 'missing');
                
                const sessionId = cookie?.match(/session_id=([a-f0-9-]+)/)?.[1];
                console.log(`[DEBUG] Session ID extracted:`, sessionId ? 'present' : 'missing');
                
                if (!sessionId) {
                    console.log(`[DEBUG] No session ID found`);
                    return new Response(JSON.stringify({
                        error: "No authenticated session found",
                        message: "Please authenticate with Spotify first by visiting /auth"
                    }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                
                const doId = env.SPOTIFY_SESSION.idFromString(sessionId);
                const sessionStub = env.SPOTIFY_SESSION.get(doId);
                console.log(`[DEBUG] Session stub created`);
                
                const validToken = await getValidAccessToken(sessionStub);
                console.log(`[DEBUG] Valid token check:`, validToken ? 'present' : 'missing');
                
                if (!validToken) {
                    console.log(`[DEBUG] Session expired or invalid`);
                    return new Response(JSON.stringify({
                        error: "Session expired",
                        message: "Please re-authenticate with Spotify by visiting /auth"
                    }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                
                // Generate API key and create dedicated session for it
                const apiKey = crypto.randomUUID();
                console.log(`[DEBUG] Generated API key:`, apiKey);
                
                // Create a new session specifically for this API key using idFromName
                const apiKeyDoId = env.SPOTIFY_SESSION.idFromName(`api-key-${apiKey}`);
                const apiKeyStub = env.SPOTIFY_SESSION.get(apiKeyDoId);
                console.log(`[DEBUG] Created API key session with name:`, `api-key-${apiKey}`);
                
                // Copy tokens from current session to API key session
                const tokens = await getTokensFromSession(sessionStub);
                console.log(`[DEBUG] Tokens retrieved:`, tokens ? 'present' : 'missing');
                
                if (tokens) {
                    await apiKeyStub.fetch(new Request('http://localhost/setTokens', {
                        method: 'POST',
                        body: JSON.stringify({
                            access_token: tokens.accessToken,
                            refresh_token: tokens.refreshToken,
                            expires_in: Math.floor((tokens.expiresAt - Date.now()) / 1000)
                        })
                    }));
                    
                    // Store the API key in this session for verification
                    await apiKeyStub.fetch(new Request('http://localhost/setApiKey', {
                        method: 'POST',
                        body: JSON.stringify({
                            apiKey: apiKey
                        })
                    }));
                    
                    console.log(`[DEBUG] API key session created and tokens stored`);
                }
                
                return new Response(JSON.stringify({
                    api_key: apiKey,
                    message: "API key generated successfully. You can use this key in multiple ways for MCP requests.",
                    instructions: {
                        "URL Parameter (Recommended)": `https://spotify-mcp-worker.aike-357.workers.dev/mcp?api_key=${apiKey}`,
                        "Authorization Header": `Authorization: Bearer ${apiKey}`,
                        "Alternative URL Parameter": `https://spotify-mcp-worker.aike-357.workers.dev/mcp?key=${apiKey}`
                    }
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
                
            } catch (error) {
                console.log(`[DEBUG] Error in API key generation:`, error);
                return new Response(JSON.stringify({
                    error: "Internal server error",
                    message: error instanceof Error ? error.message : 'Unknown error occurred'
                }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
        
        // Simple authentication check endpoint
        if (url.pathname === "/auth-check") {
            const cookie = request.headers.get("Cookie");
            const sessionId = cookie?.match(/session_id=([a-f0-9-]+)/)?.[1];
            
            if (sessionId) {
                const doId = env.SPOTIFY_SESSION.idFromString(sessionId);
                const sessionStub = env.SPOTIFY_SESSION.get(doId);
                const validToken = await getValidAccessToken(sessionStub);
                
                if (validToken) {
                    return new Response(JSON.stringify({
                        status: "authenticated",
                        message: "You are authenticated with Spotify and can use the MCP tools.",
                        session_id: sessionId,
                        generate_api_key_url: "https://spotify-mcp-worker.aike-357.workers.dev/generate-api-key"
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            }
            
            return new Response(JSON.stringify({
                status: "unauthenticated",
                message: "Please authenticate with Spotify to use the MCP tools.",
                auth_url: "https://spotify-mcp-worker.aike-357.workers.dev/auth",
                instructions: "Visit the auth_url in your browser to authenticate with Spotify"
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        return new Response("Not found.", { status: 404 });
    }
};

// Helper function to get valid access token from Durable Object
async function getValidAccessToken(sessionStub: DurableObjectStub): Promise<string | null> {
    const response = await sessionStub.fetch(new Request('http://localhost/getValidAccessToken'));
    if (response.ok) {
        const data = await response.json() as { token: string | null };
        return data.token;
    }
    return null;
}

// Helper function to get session from cookie
async function getSessionFromCookie(request: Request, env: Env): Promise<DurableObjectStub | null> {
    const cookie = request.headers.get("Cookie");
    const sessionId = cookie?.match(/session_id=([a-f0-9-]+)/)?.[1];
    
    if (!sessionId) {
        return null;
    }
    
    const doId = env.SPOTIFY_SESSION.idFromString(sessionId);
    const sessionStub = env.SPOTIFY_SESSION.get(doId);
    
    // Verify session has valid tokens
    const validToken = await getValidAccessToken(sessionStub);
    return validToken ? sessionStub : null;
}

// Helper function to get tokens from session
async function getTokensFromSession(sessionStub: DurableObjectStub): Promise<any | null> {
    try {
        const response = await sessionStub.fetch(new Request('http://localhost/getTokens'));
        if (response.ok) {
            const data = await response.json();
            return data;
        }
        console.log(`[DEBUG] Failed to get tokens from session, status:`, response.status);
        return null;
    } catch (error) {
        console.log(`[DEBUG] Error getting tokens from session:`, error);
        return null;
    }
}

// Helper function to validate UUID format
function isValidUUID(str: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(str);
}

// Helper function to find session by API key
async function findSessionByApiKey(apiKey: string, env: Env): Promise<DurableObjectStub | null> {
    try {
        console.log(`[DEBUG] Looking for API key session:`, `api-key-${apiKey}`);
        
        // Use idFromName to find the session for this API key
        const doId = env.SPOTIFY_SESSION.idFromName(`api-key-${apiKey}`);
        const sessionStub = env.SPOTIFY_SESSION.get(doId);
        
        // Check if this session has valid tokens
        const validToken = await getValidAccessToken(sessionStub);
        if (validToken) {
            console.log(`[DEBUG] Found valid API key session`);
            return sessionStub;
        } else {
            console.log(`[DEBUG] API key session exists but no valid tokens`);
            return null;
        }
    } catch (error) {
        console.log(`[DEBUG] Error in findSessionByApiKey:`, error);
        return null;
    }
}

// Token validation function for MCP authorization
async function validateTokenAndGetSession(token: string, env: Env): Promise<DurableObjectStub | null> {
    try {
        console.log(`[DEBUG] Validating token:`, token.substring(0, 20) + '...');
        
        // For now, we'll use a simple token format: "session_id:spotify_access_token"
        const [sessionId, spotifyToken] = token.split(':');
        
        console.log(`[DEBUG] Token parts:`, { sessionId: sessionId ? 'present' : 'missing', spotifyToken: spotifyToken ? 'present' : 'missing' });
        
        if (!sessionId || !spotifyToken) {
            console.log(`[DEBUG] Token format invalid`);
            return null;
        }
        
        const doId = env.SPOTIFY_SESSION.idFromString(sessionId);
        const sessionStub = env.SPOTIFY_SESSION.get(doId);
        
        console.log(`[DEBUG] Session ID:`, doId.toString());
        
        // Verify the session has a valid Spotify token
        const validToken = await getValidAccessToken(sessionStub);
        console.log(`[DEBUG] Valid token from session:`, validToken ? 'present' : 'missing');
        
        if (validToken === spotifyToken) {
            console.log(`[DEBUG] Token validation successful`);
            return sessionStub;
        }
        
        console.log(`[DEBUG] Token validation failed - tokens don't match`);
        return null;
    } catch (error) {
        console.log(`[DEBUG] Token validation error:`, error);
        return null;
    }
}

// HTTP MCP request handler
async function handleMcpRequest(request: Request, sessionStub: DurableObjectStub | null): Promise<Response> {
    const method = request.method;
    
    if (method === 'GET') {
        // Return MCP server info (for discovery)
        return new Response(JSON.stringify({
            name: "spotify",
            version: "1.0.0",
            description: "Spotify MCP Server",
            capabilities: {
                tools: {
                    listChanged: false
                }
            }
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
    
    if (method === 'POST') {
        try {
            const body = await request.json() as any;
            console.log(`[DEBUG] Request body:`, JSON.stringify(body, null, 2));
            
            // Handle JSON-RPC 2.0 requests
            if (body.jsonrpc === '2.0') {
                console.log(`[DEBUG] Processing JSON-RPC 2.0 request:`, body.method);
                return handleJsonRpcRequest(body, sessionStub);
            }
            
            // Legacy support for non-JSON-RPC requests
            if (body.method === 'tools/list') {
                // Return available tools in proper MCP format
                console.log(`[DEBUG] Legacy tools list requested, authenticated: ${!!sessionStub}`);
                const authNotice = !sessionStub ? 
                    " Note: Authentication required - visit https://spotify-mcp-worker.aike-357.workers.dev/auth first." : 
                    "";
                
                return new Response(JSON.stringify({
                    tools: [
                        {
                            name: "spotify:get-playlists",
                            description: `Get user's playlists from Spotify.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {},
                                additionalProperties: false
                            }
                        },
                        {
                            name: "spotify:create-playlist",
                            description: `Create a new Spotify playlist.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {
                                    name: { 
                                        type: "string",
                                        description: "Name of the playlist"
                                    },
                                    description: { 
                                        type: "string",
                                        description: "Description of the playlist"
                                    },
                                    public: { 
                                        type: "boolean",
                                        description: "Whether the playlist should be public"
                                    }
                                },
                                required: ["name"],
                                additionalProperties: false
                            }
                        },
                        {
                            name: "spotify:get-profile",
                            description: `Get user's Spotify profile.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {},
                                additionalProperties: false
                            }
                        },
                        {
                            name: "spotify:play-track",
                            description: `Play a track on Spotify.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {
                                    uri: { 
                                        type: "string",
                                        description: "Spotify URI of the track to play"
                                    },
                                    deviceId: { 
                                        type: "string",
                                        description: "Optional device ID to play on"
                                    }
                                },
                                required: ["uri"],
                                additionalProperties: false
                            }
                        }
                    ]
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            
            if (body.method === 'tools/call') {
                const { name, arguments: args } = body.params;
                
                // Check authentication for tool calls
                if (!sessionStub) {
                    return new Response(JSON.stringify({
                        content: [{ 
                            type: "text", 
                            text: "Authentication required to use Spotify tools. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." 
                        }]
                    }), { 
                        status: 401,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                
                // Handle tool calls
                switch (name) {
                    case 'spotify:get-playlists':
                        return await handleGetPlaylists(sessionStub);
                    case 'spotify:create-playlist':
                        return await handleCreatePlaylist(sessionStub, args);
                    case 'spotify:get-profile':
                        return await handleGetProfile(sessionStub);
                    case 'spotify:play-track':
                        return await handlePlayTrack(sessionStub, args);
                    default:
                        return new Response(JSON.stringify({
                            error: { message: `Unknown tool: ${name}` }
                        }), { 
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                }
            }
            
            return new Response(JSON.stringify({
                error: { message: `Unknown method: ${body.method}` }
            }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
            
        } catch (error) {
            console.log(`[DEBUG] Error in handleMcpRequest:`, error);
            return new Response(JSON.stringify({
                error: { message: error instanceof Error ? error.message : 'Unknown error' }
            }), { 
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    
    return new Response('Method not allowed', { status: 405 });
}

// Tool handlers
async function handleGetPlaylists(sessionStub: DurableObjectStub): Promise<Response> {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{ 
                    type: "text", 
                    text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." 
                }]
            }), { 
                status: 401,
                headers: { 'Content-Type': 'application/json' } 
            });
        }
        
        const response = await fetch("https://api.spotify.com/v1/me/playlists", {
            headers: { "Authorization": `Bearer ${accessToken}` }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to get playlists: ${response.statusText}`);
        }
        
        const data = await response.json();
        return new Response(JSON.stringify({
            content: [{ type: "json", json: data }]
        }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}

async function handleCreatePlaylist(sessionStub: DurableObjectStub, args: any): Promise<Response> {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{ 
                    type: "text", 
                    text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." 
                }]
            }), { 
                status: 401,
                headers: { 'Content-Type': 'application/json' } 
            });
        }
        
        const userResponse = await fetch("https://api.spotify.com/v1/me", {
            headers: { "Authorization": `Bearer ${accessToken}` }
        });
        
        if (!userResponse.ok) {
            throw new Error(`Failed to get user profile: ${userResponse.statusText}`);
        }
        
        const user = await userResponse.json() as { id: string };
        
        const response = await fetch(`https://api.spotify.com/v1/users/${user.id}/playlists`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: args.name,
                description: args.description,
                public: args.public ?? false
            })
        });

        if (!response.ok) {
            throw new Error(`Failed to create playlist: ${response.statusText}`);
        }

        const playlist = await response.json();
        return new Response(JSON.stringify({
            content: [{ type: "json", json: playlist }]
        }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}

async function handleGetProfile(sessionStub: DurableObjectStub): Promise<Response> {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{ 
                    type: "text", 
                    text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." 
                }]
            }), { 
                status: 401,
                headers: { 'Content-Type': 'application/json' } 
            });
        }

        const response = await fetch("https://api.spotify.com/v1/me", {
            headers: { "Authorization": `Bearer ${accessToken}` }
        });

        if (!response.ok) {
            throw new Error(`Failed to get profile: ${response.statusText}`);
        }

        const profile = await response.json();
        return new Response(JSON.stringify({
            content: [{ type: "json", json: profile }]
        }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}

async function handlePlayTrack(sessionStub: DurableObjectStub, args: any): Promise<Response> {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{ 
                    type: "text", 
                    text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again." 
                }]
            }), { 
                status: 401,
                headers: { 'Content-Type': 'application/json' } 
            });
        }

        const endpoint = args.deviceId ? 
            `https://api.spotify.com/v1/me/player/play?device_id=${args.deviceId}` :
            'https://api.spotify.com/v1/me/player/play';

        const response = await fetch(endpoint, {
            method: "PUT",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                uris: [args.uri]
            })
        });

        if (!response.ok) {
            throw new Error(`Failed to start playback: ${response.statusText}`);
        }

        return new Response(JSON.stringify({
            content: [{ type: "text", text: "Playback started successfully" }]
        }), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}

// JSON-RPC 2.0 handler for MCP protocol
async function handleJsonRpcRequest(body: any, sessionStub: DurableObjectStub | null): Promise<Response> {
    const { id, method, params } = body;
    
    console.log(`[DEBUG] JSON-RPC method:`, method, `params:`, params);
    
    // Handle notifications (no id field) - these don't expect responses
    if (id === undefined) {
        console.log(`[DEBUG] Handling notification: ${method}`);
        if (method === 'notifications/initialized') {
            console.log(`[DEBUG] Client initialized successfully`);
            console.log(`[DEBUG] Client should now call tools/list to discover available tools`);
        }
        // Return empty response for notifications
        return new Response('', { status: 200 });
    }
    
    try {
        let result: any;
        
        switch (method) {
            case 'initialize':
                // Use the client's protocol version if it's supported
                const clientProtocolVersion = params?.protocolVersion || "2024-11-05";
                const supportedVersions = ["2024-11-05", "2025-06-18"];
                const negotiatedVersion = supportedVersions.includes(clientProtocolVersion) ? clientProtocolVersion : "2024-11-05";
                
                console.log(`[DEBUG] Protocol version negotiation: client=${clientProtocolVersion}, negotiated=${negotiatedVersion}`);
                
                result = {
                    protocolVersion: negotiatedVersion,
                    capabilities: {
                        tools: {}
                    },
                    serverInfo: {
                        name: "spotify",
                        version: "1.0.0",
                        description: "Spotify MCP Server with playlist management and playback control"
                    }
                };
                break;
                
            case 'tools/list':
                console.log(`[DEBUG] Tools list requested, authenticated: ${!!sessionStub}`);
                const authNotice = !sessionStub ? 
                    " Note: Authentication required - visit https://spotify-mcp-worker.aike-357.workers.dev/auth first." : 
                    "";
                    
                result = {
                    tools: [
                        {
                            name: "spotify:get-playlists",
                            description: `Get user's playlists from Spotify.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {},
                                additionalProperties: false
                            }
                        },
                        {
                            name: "spotify:create-playlist",
                            description: `Create a new Spotify playlist.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {
                                    name: { 
                                        type: "string",
                                        description: "Name of the playlist"
                                    },
                                    description: { 
                                        type: "string",
                                        description: "Description of the playlist"
                                    },
                                    public: { 
                                        type: "boolean",
                                        description: "Whether the playlist should be public"
                                    }
                                },
                                required: ["name"],
                                additionalProperties: false
                            }
                        },
                        {
                            name: "spotify:get-profile",
                            description: `Get user's Spotify profile.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {},
                                additionalProperties: false
                            }
                        },
                        {
                            name: "spotify:play-track",
                            description: `Play a track on Spotify.${authNotice}`,
                            inputSchema: {
                                type: "object",
                                properties: {
                                    uri: { 
                                        type: "string",
                                        description: "Spotify URI of the track to play"
                                    },
                                    deviceId: { 
                                        type: "string",
                                        description: "Optional device ID to play on"
                                    }
                                },
                                required: ["uri"],
                                additionalProperties: false
                            }
                        }
                    ]
                };
                break;
                
            case 'tools/call':
                if (!sessionStub) {
                    throw new Error("Authentication required to use Spotify tools. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again.");
                }
                
                const { name, arguments: args } = params;
                
                switch (name) {
                    case 'spotify:get-playlists':
                        const playlistsResponse = await handleGetPlaylists(sessionStub);
                        const playlistsData = await playlistsResponse.json();
                        result = playlistsData;
                        break;
                    case 'spotify:create-playlist':
                        const createResponse = await handleCreatePlaylist(sessionStub, args);
                        const createData = await createResponse.json();
                        result = createData;
                        break;
                    case 'spotify:get-profile':
                        const profileResponse = await handleGetProfile(sessionStub);
                        const profileData = await profileResponse.json();
                        result = profileData;
                        break;
                    case 'spotify:play-track':
                        const playResponse = await handlePlayTrack(sessionStub, args);
                        const playData = await playResponse.json();
                        result = playData;
                        break;
                    default:
                        throw new Error(`Unknown tool: ${name}`);
                }
                break;
                
            default:
                throw new Error(`Unknown method: ${method}`);
        }
        
        const response = {
            jsonrpc: "2.0",
            id,
            result
        };
        console.log(`[DEBUG] JSON-RPC response:`, JSON.stringify(response, null, 2));
        
        return new Response(JSON.stringify(response), {
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        console.log(`[DEBUG] JSON-RPC error:`, error);
        const errorResponse = {
            jsonrpc: "2.0",
            id,
            error: {
                code: -32603,
                message: error instanceof Error ? error.message : 'Internal error'
            }
        };
        console.log(`[DEBUG] JSON-RPC error response:`, JSON.stringify(errorResponse, null, 2));
        
        return new Response(JSON.stringify(errorResponse), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
} 