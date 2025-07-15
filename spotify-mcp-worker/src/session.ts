export class SpotifySession {
    state: DurableObjectState;
    env: Env;

    constructor(state: DurableObjectState, env: Env) {
        this.state = state;
        this.env = env;
    }

    // Handle fetch requests to the Durable Object
    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        
        if (url.pathname === '/setTokens') {
            const tokens = await request.json() as { access_token: string; refresh_token: string; expires_in: number };
            await this.setTokens(tokens);
            return new Response('OK', { status: 200 });
        }
        
        if (url.pathname === '/getValidAccessToken') {
            const token = await this.getValidAccessToken();
            return new Response(JSON.stringify({ token }), { 
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        
        if (url.pathname === '/getTokens') {
            const tokens = await this.getTokens();
            return new Response(JSON.stringify(tokens), { 
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        
        return new Response('Not found', { status: 404 });
    }

    // Stores the tokens provided by Spotify's OAuth flow
    async setTokens(tokens: { access_token: string; refresh_token: string; expires_in: number }) {
        const tokenData = {
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
            expiresAt: Date.now() + tokens.expires_in * 1000,
        };
        await this.state.storage.put("spotifyTokens", tokenData);
    }

    // Retrieves a valid access token, refreshing if necessary
    async getValidAccessToken(): Promise<string | null> {
        let tokens: any = await this.state.storage.get("spotifyTokens");
        if (!tokens) return null;

        if (Date.now() >= tokens.expiresAt - 60 * 1000) {
            // Token is expired or about to expire, refresh it
            const auth = new SpotifyAuth(this.env);
            const newTokens = await auth.refreshAccessToken(tokens.refreshToken);
            await this.setTokens(newTokens);
            return newTokens.access_token;
        }
        return tokens.accessToken;
    }

    // Get stored tokens
    async getTokens(): Promise<any> {
        return await this.state.storage.get("spotifyTokens");
    }
}

// Environment interface for Cloudflare Worker
export interface Env {
    SPOTIFY_CLIENT_ID: string;
    SPOTIFY_CLIENT_SECRET: string;
    SPOTIFY_SESSION: DurableObjectNamespace;
}

// SpotifyAuth class adapted for Cloudflare Workers
export class SpotifyAuth {
    private clientId: string;
    private clientSecret: string;

    constructor(env: Env) {
        this.clientId = env.SPOTIFY_CLIENT_ID;
        this.clientSecret = env.SPOTIFY_CLIENT_SECRET;
    }

    /**
     * Generate the authorization URL for Spotify OAuth
     */
    generateAuthUrl(host: string): { url: string; state: string } {
        const state = crypto.randomUUID();
        
        const params = new URLSearchParams({
            client_id: this.clientId,
            response_type: 'code',
            redirect_uri: `https://${host}/callback`,
            state: state,
            scope: 'user-library-read playlist-read-private playlist-modify-public playlist-modify-private',
        });

        return {
            url: `https://accounts.spotify.com/authorize?${params.toString()}`,
            state,
        };
    }

    /**
     * Exchange authorization code for access and refresh tokens
     */
    async getAccessToken(code: string, state: string, host: string): Promise<{
        access_token: string;
        refresh_token: string;
        expires_in: number;
    }> {
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: `https://${host}/callback`,
        });

        const response = await fetch('https://accounts.spotify.com/api/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: params.toString(),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to get access token: ${error}`);
        }

        return await response.json();
    }

    /**
     * Refresh the access token using the refresh token
     */
    async refreshAccessToken(refreshToken: string): Promise<{
        access_token: string;
        refresh_token: string;
        expires_in: number;
    }> {
        const params = new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
        });

        const response = await fetch('https://accounts.spotify.com/api/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: params.toString(),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to refresh token: ${error}`);
        }

        return await response.json();
    }
} 