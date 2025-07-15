import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Env } from './session';

// Durable Object MCP Agent for Spotify
export class SpotifyMCPAgent extends McpAgent<Env, Record<string, never>, Record<string, never>> {
    server = new McpServer({
        name: "Spotify MCP Server",
        version: "1.0.0",
    });

    async init() {
        // Register all Spotify tools
        this.server.tool(
            "spotify:get-playlists",
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
        this.server.tool(
            "spotify:create-playlist",
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
        this.server.tool(
            "spotify:get-profile",
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
        this.server.tool(
            "spotify:play-track",
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
        this.server.tool(
            "spotify:search",
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

    // --- Session and token helpers (copied from previous implementation) ---
    private async getSessionStub(): Promise<DurableObjectStub | null> {
        // ... (copy from previous implementation)
        // This should look up the session Durable Object for the current request
        // and return the stub, or null if not found.
        // You may need to adapt this to the new context if needed.
        return null; // TODO: implement
    }
    private async getValidAccessToken(sessionStub: DurableObjectStub | null): Promise<string | null> {
        // ... (copy from previous implementation)
        // This should return a valid access token for the session, or null if not authenticated.
        return null; // TODO: implement
    }
}

// Export for Durable Object binding
export { SpotifyMCPAgent as McpAgent };