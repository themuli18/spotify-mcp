import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
// Create server instance
const server = new McpServer({
    name: "spotify",
    version: "1.0.0",
    capabilities: {
        resources: {},
        tools: {},
    },
});
// Constants
const WORKER_URL = "https://spotify-mcp-worker.aike-357.workers.dev";
// Helper function to make requests to our Cloudflare Worker
async function makeWorkerRequest(endpoint, options = {}) {
    try {
        const response = await fetch(`${WORKER_URL}${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }
    catch (error) {
        console.error("Error making worker request:", error);
        return null;
    }
}
// Helper function to check authentication status
async function checkAuthStatus() {
    const result = await makeWorkerRequest("/auth-check");
    if (!result) {
        return { authenticated: false, message: "Unable to connect to authentication service" };
    }
    return result;
}
// Register Spotify tools
server.tool("get-playlists", "Get user's playlists from Spotify", {}, async () => {
    const authStatus = await checkAuthStatus();
    if (!authStatus.authenticated) {
        return {
            content: [
                {
                    type: "text",
                    text: `Authentication required. Please visit ${WORKER_URL}/auth to authenticate with Spotify, then try again.`,
                },
            ],
        };
    }
    const result = await makeWorkerRequest("/mcp", {
        method: "POST",
        body: JSON.stringify({
            method: "tools/call",
            params: {
                name: "spotify:get-playlists",
                arguments: {}
            }
        })
    });
    if (!result || result.error) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error: ${result?.error?.message || "Failed to get playlists"}`,
                },
            ],
        };
    }
    return {
        content: result.content || [{ type: "text", text: "No playlists found" }],
    };
});
server.tool("create-playlist", "Create a new Spotify playlist", {
    name: z.string().describe("Name of the playlist"),
    description: z.string().optional().describe("Description of the playlist"),
    public: z.boolean().optional().describe("Whether the playlist should be public"),
}, async ({ name, description, public: isPublic }) => {
    const authStatus = await checkAuthStatus();
    if (!authStatus.authenticated) {
        return {
            content: [
                {
                    type: "text",
                    text: `Authentication required. Please visit ${WORKER_URL}/auth to authenticate with Spotify, then try again.`,
                },
            ],
        };
    }
    const result = await makeWorkerRequest("/mcp", {
        method: "POST",
        body: JSON.stringify({
            method: "tools/call",
            params: {
                name: "spotify:create-playlist",
                arguments: {
                    name,
                    description,
                    public: isPublic
                }
            }
        })
    });
    if (!result || result.error) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error: ${result?.error?.message || "Failed to create playlist"}`,
                },
            ],
        };
    }
    return {
        content: result.content || [{ type: "text", text: "Playlist created successfully" }],
    };
});
server.tool("get-profile", "Get user's Spotify profile", {}, async () => {
    const authStatus = await checkAuthStatus();
    if (!authStatus.authenticated) {
        return {
            content: [
                {
                    type: "text",
                    text: `Authentication required. Please visit ${WORKER_URL}/auth to authenticate with Spotify, then try again.`,
                },
            ],
        };
    }
    const result = await makeWorkerRequest("/mcp", {
        method: "POST",
        body: JSON.stringify({
            method: "tools/call",
            params: {
                name: "spotify:get-profile",
                arguments: {}
            }
        })
    });
    if (!result || result.error) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error: ${result?.error?.message || "Failed to get profile"}`,
                },
            ],
        };
    }
    return {
        content: result.content || [{ type: "text", text: "Profile not found" }],
    };
});
server.tool("play-track", "Play a track on Spotify", {
    uri: z.string().describe("Spotify track URI (e.g., spotify:track:4iV5W9uYEdYUVa79Axb7Rh)"),
    deviceId: z.string().optional().describe("Device ID to play on (optional)"),
}, async ({ uri, deviceId }) => {
    const authStatus = await checkAuthStatus();
    if (!authStatus.authenticated) {
        return {
            content: [
                {
                    type: "text",
                    text: `Authentication required. Please visit ${WORKER_URL}/auth to authenticate with Spotify, then try again.`,
                },
            ],
        };
    }
    const result = await makeWorkerRequest("/mcp", {
        method: "POST",
        body: JSON.stringify({
            method: "tools/call",
            params: {
                name: "spotify:play-track",
                arguments: {
                    uri,
                    deviceId
                }
            }
        })
    });
    if (!result || result.error) {
        return {
            content: [
                {
                    type: "text",
                    text: `Error: ${result?.error?.message || "Failed to play track"}`,
                },
            ],
        };
    }
    return {
        content: result.content || [{ type: "text", text: "Track playback started" }],
    };
});
// Run the server
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Spotify MCP Server (stdio proxy) running");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
