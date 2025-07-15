import crypto from 'crypto';
import { URLSearchParams } from 'url';

// Scopes we want to request from Spotify
const SPOTIFY_SCOPES = [
    'user-library-read',
    'playlist-read-private',
    'playlist-modify-public',
    'playlist-modify-private',
];

// Store state and tokens in memory (for development)
// In production, use a proper database or secure storage
const stateStore = new Map<string, { expiresAt: number }>();
const tokenStore = new Map<string, {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
}>();

export class SpotifyAuth {
    private clientId: string;
    private clientSecret: string;
    private redirectUri: string;

    constructor() {
        const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, SPOTIFY_REDIRECT_URI } = process.env;

        // Debug logging
        console.log('Environment variables:', {
            SPOTIFY_CLIENT_ID: SPOTIFY_CLIENT_ID ? 'present' : 'missing',
            SPOTIFY_CLIENT_SECRET: SPOTIFY_CLIENT_SECRET ? 'present' : 'missing',
            SPOTIFY_REDIRECT_URI: SPOTIFY_REDIRECT_URI ? 'present' : 'missing'
        });

        if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET || !SPOTIFY_REDIRECT_URI) {
            throw new Error('Missing required Spotify credentials in environment variables');
        }

        this.clientId = SPOTIFY_CLIENT_ID;
        this.clientSecret = SPOTIFY_CLIENT_SECRET;
        this.redirectUri = SPOTIFY_REDIRECT_URI;
    }

    /**
     * Generate the authorization URL for Spotify OAuth
     */
    generateAuthUrl(host?: string): { url: string; state: string } {
        const state = crypto.randomBytes(16).toString('hex');
        
        // Store state with expiration (5 minutes)
        stateStore.set(state, {
            expiresAt: Date.now() + 5 * 60 * 1000,
        });

        // Use the provided host or fall back to the configured redirect URI
        const effectiveRedirectUri = host ? 
            `https://${host}/callback` : 
            this.redirectUri;

        console.log('Using redirect URI:', effectiveRedirectUri);

        const params = new URLSearchParams({
            client_id: this.clientId,
            response_type: 'code',
            redirect_uri: effectiveRedirectUri,
            state: state,
            scope: SPOTIFY_SCOPES.join(' '),
        });

        return {
            url: `https://accounts.spotify.com/authorize?${params.toString()}`,
            state,
        };
    }

    /**
     * Exchange authorization code for access and refresh tokens
     */
    async getAccessToken(code: string, state: string, host?: string): Promise<{
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }> {
        // Verify state
        const storedState = stateStore.get(state);
        if (!storedState || storedState.expiresAt < Date.now()) {
            throw new Error('Invalid or expired state');
        }
        stateStore.delete(state);

        // Use the provided host or fall back to the configured redirect URI
        const effectiveRedirectUri = host ? 
            `https://${host}/callback` : 
            this.redirectUri;

        console.log('Using callback URI:', effectiveRedirectUri);

        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: effectiveRedirectUri,
        });

        const response = await fetch('https://accounts.spotify.com/api/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: params.toString(),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to get access token: ${error}`);
        }

        const data = await response.json();
        
        // Store tokens with expiration
        tokenStore.set('spotify', {
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            expiresAt: Date.now() + (data.expires_in * 1000),
        });

        return {
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            expiresIn: data.expires_in,
        };
    }

    /**
     * Refresh the access token using the refresh token
     */
    async refreshAccessToken(refreshToken: string): Promise<{
        accessToken: string;
        expiresIn: number;
    }> {
        const params = new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
        });

        const response = await fetch('https://accounts.spotify.com/api/token', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: params.toString(),
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(`Failed to refresh token: ${error}`);
        }

        const data = await response.json();

        // Update stored token
        const storedTokens = tokenStore.get('spotify');
        if (storedTokens) {
            tokenStore.set('spotify', {
                ...storedTokens,
                accessToken: data.access_token,
                expiresAt: Date.now() + (data.expires_in * 1000),
            });
        }

        return {
            accessToken: data.access_token,
            expiresIn: data.expires_in,
        };
    }

    /**
     * Get a valid access token, refreshing if necessary
     */
    async getValidAccessToken(): Promise<string> {
        const tokens = tokenStore.get('spotify');
        if (!tokens) {
            throw new Error('No tokens available. User needs to authenticate.');
        }

        // If token is expired or will expire in the next 5 minutes, refresh it
        if (tokens.expiresAt <= Date.now() + 5 * 60 * 1000) {
            const { accessToken } = await this.refreshAccessToken(tokens.refreshToken);
            return accessToken;
        }

        return tokens.accessToken;
    }

    /**
     * Get user's playlists
     */
    async getPlaylists(): Promise<any> {
        const accessToken = await this.getValidAccessToken();
        const response = await fetch('https://api.spotify.com/v1/me/playlists', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Failed to get playlists: ${response.statusText}`);
        }

        return response.json();
    }

    /**
     * Start playback on a device
     */
    async play(uri: string, deviceId?: string): Promise<void> {
        const accessToken = await this.getValidAccessToken();
        const endpoint = deviceId ? 
            `https://api.spotify.com/v1/me/player/play?device_id=${deviceId}` :
            'https://api.spotify.com/v1/me/player/play';

        const response = await fetch(endpoint, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                uris: [uri],
            }),
        });

        if (!response.ok) {
            throw new Error(`Failed to start playback: ${response.statusText}`);
        }
    }
} 