import { SpotifyAuth, SpotifySession } from './session';
export default {
    async fetch(request, env, ctx) {
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
            return Response.redirect(authUrl, 302);
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
            }
            catch (error) {
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
                }
                else {
                    // Legacy direct OAuth flow
                    const tokens = await auth.getAccessToken(code, state, host);
                    const doId = env.SPOTIFY_SESSION.newUniqueId();
                    const stub = env.SPOTIFY_SESSION.get(doId);
                    await stub.fetch(new Request('http://localhost/setTokens', {
                        method: 'POST',
                        body: JSON.stringify(tokens)
                    }));
                    const response = new Response("Success! You can close this window.", { status: 200 });
                    response.headers.set("Set-Cookie", `session_id=${doId.toString()}; HttpOnly; Secure; Path=/; SameSite=Strict`);
                    return response;
                }
            }
            catch (error) {
                return new Response(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`, { status: 500 });
            }
        }
        // HTTP MCP route
        if (url.pathname === "/mcp") {
            console.log(`[DEBUG] MCP request received`);
            const method = request.method;
            // Check for Authorization header
            const authHeader = request.headers.get("Authorization");
            console.log(`[DEBUG] Authorization header:`, authHeader ? 'present' : 'missing');
            // Check for session cookie as fallback
            const cookie = request.headers.get("Cookie");
            const sessionId = cookie?.match(/session_id=([a-f0-9-]+)/)?.[1];
            console.log(`[DEBUG] Session cookie:`, sessionId ? 'present' : 'missing');
            let sessionStub = null;
            if (authHeader && authHeader.startsWith("Bearer ")) {
                // OAuth 2.1 Bearer token flow
                const token = authHeader.substring(7);
                console.log(`[DEBUG] Token received:`, token.substring(0, 20) + '...');
                sessionStub = await validateTokenAndGetSession(token, env);
                if (sessionStub) {
                    console.log(`[DEBUG] OAuth token validated successfully`);
                }
                else {
                    console.log(`[DEBUG] OAuth token validation failed`);
                }
            }
            else if (sessionId) {
                // Session cookie flow (fallback)
                console.log(`[DEBUG] Using session cookie flow`);
                const doId = env.SPOTIFY_SESSION.idFromString(sessionId);
                sessionStub = env.SPOTIFY_SESSION.get(doId);
                // Verify session has valid tokens
                const validToken = await getValidAccessToken(sessionStub);
                if (!validToken) {
                    console.log(`[DEBUG] Session has no valid tokens`);
                    sessionStub = null;
                }
                else {
                    console.log(`[DEBUG] Session validated successfully`);
                }
            }
            if (!sessionStub) {
                console.log(`[DEBUG] No valid authentication, returning MCP server info with auth notice`);
                // Return standard MCP server information
                return new Response(JSON.stringify({
                    name: "spotify",
                    version: "1.0.0",
                    capabilities: {
                        tools: {
                            listChanged: false
                        }
                    }
                }), {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
            }
            // Handle MCP requests
            return handleMcpRequest(request, sessionStub);
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
        // Health check endpoint
        if (url.pathname === "/health") {
            return new Response("OK", { status: 200 });
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
            }
            else {
                return new Response(JSON.stringify({
                    authenticated: false,
                    message: "No session found",
                    auth_url: "https://spotify-mcp-worker.aike-357.workers.dev/auth"
                }), {
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
                        message: "You are authenticated with Spotify and can use the MCP tools."
                    }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            }
            return new Response(JSON.stringify({
                status: "unauthenticated",
                message: "Please authenticate with Spotify to use the MCP tools.",
                auth_url: "https://spotify-mcp-worker.aike-357.workers.dev/auth"
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return new Response("Not found.", { status: 404 });
    }
};
export { SpotifySession };
// Helper function to get valid access token from Durable Object
async function getValidAccessToken(sessionStub) {
    const response = await sessionStub.fetch(new Request('http://localhost/getValidAccessToken'));
    if (response.ok) {
        const data = await response.json();
        return data.token;
    }
    return null;
}
// Token validation function for MCP authorization
async function validateTokenAndGetSession(token, env) {
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
    }
    catch (error) {
        console.log(`[DEBUG] Token validation error:`, error);
        return null;
    }
}
// HTTP MCP request handler
async function handleMcpRequest(request, sessionStub) {
    const method = request.method;
    if (method === 'GET') {
        // Return MCP server info
        return new Response(JSON.stringify({
            name: "spotify",
            version: "1.0.0",
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
            const body = await request.json();
            if (body.method === 'tools/list') {
                // Return available tools in proper MCP format
                return new Response(JSON.stringify({
                    tools: [
                        {
                            name: "spotify:get-playlists",
                            description: "Get user's playlists from Spotify. Requires authentication - visit https://spotify-mcp-worker.aike-357.workers.dev/auth first.",
                            inputSchema: {}
                        },
                        {
                            name: "spotify:create-playlist",
                            description: "Create a new Spotify playlist. Requires authentication - visit https://spotify-mcp-worker.aike-357.workers.dev/auth first.",
                            inputSchema: {
                                type: "object",
                                properties: {
                                    name: { type: "string" },
                                    description: { type: "string" },
                                    public: { type: "boolean" }
                                },
                                required: ["name"]
                            }
                        },
                        {
                            name: "spotify:get-profile",
                            description: "Get user's Spotify profile. Requires authentication - visit https://spotify-mcp-worker.aike-357.workers.dev/auth first.",
                            inputSchema: {}
                        },
                        {
                            name: "spotify:play-track",
                            description: "Play a track on Spotify. Requires authentication - visit https://spotify-mcp-worker.aike-357.workers.dev/auth first.",
                            inputSchema: {
                                type: "object",
                                properties: {
                                    uri: { type: "string" },
                                    deviceId: { type: "string" }
                                },
                                required: ["uri"]
                            }
                        }
                    ]
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            if (body.method === 'tools/call') {
                const { name, arguments: args } = body.params;
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
        }
        catch (error) {
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
async function handleGetPlaylists(sessionStub) {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{
                        type: "text",
                        text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again."
                    }]
            }), { headers: { 'Content-Type': 'application/json' } });
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
    }
    catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}
async function handleCreatePlaylist(sessionStub, args) {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{
                        type: "text",
                        text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again."
                    }]
            }), { headers: { 'Content-Type': 'application/json' } });
        }
        const userResponse = await fetch("https://api.spotify.com/v1/me", {
            headers: { "Authorization": `Bearer ${accessToken}` }
        });
        if (!userResponse.ok) {
            throw new Error(`Failed to get user profile: ${userResponse.statusText}`);
        }
        const user = await userResponse.json();
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
    }
    catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}
async function handleGetProfile(sessionStub) {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{
                        type: "text",
                        text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again."
                    }]
            }), { headers: { 'Content-Type': 'application/json' } });
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
    }
    catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}
async function handlePlayTrack(sessionStub, args) {
    try {
        const accessToken = await getValidAccessToken(sessionStub);
        if (!accessToken) {
            return new Response(JSON.stringify({
                content: [{
                        type: "text",
                        text: "Authentication required. Please visit https://spotify-mcp-worker.aike-357.workers.dev/auth to authenticate with Spotify, then try again."
                    }]
            }), { headers: { 'Content-Type': 'application/json' } });
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
    }
    catch (error) {
        return new Response(JSON.stringify({
            content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}` }]
        }), { headers: { 'Content-Type': 'application/json' } });
    }
}
