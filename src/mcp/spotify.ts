import { WebSocket, WebSocketServer } from 'ws';
import { z } from 'zod';
import { SpotifyAuth } from '../auth/spotify.js';

export class SpotifyMcpServer {
    private wss: WebSocketServer;
    private spotifyAuth: SpotifyAuth;

    constructor() {
        this.spotifyAuth = new SpotifyAuth();
        this.wss = new WebSocketServer({ port: 3001 });
        this.setupWebSocket();
    }

    private setupWebSocket() {
        this.wss.on('connection', (ws: WebSocket) => {
            console.log('Client connected');

            ws.on('message', async (message: string) => {
                try {
                    const request = JSON.parse(message);
                    
                    if (request.type === 'resource') {
                        if (request.uri === 'spotify:user:profile') {
                            try {
                                const accessToken = await this.spotifyAuth.getValidAccessToken();
                                const response = await fetch('https://api.spotify.com/v1/me', {
                                    headers: {
                                        'Authorization': `Bearer ${accessToken}`,
                                    },
                                });

                                if (!response.ok) {
                                    ws.send(JSON.stringify({
                                        type: 'error',
                                        message: `Failed to retrieve user profile: ${response.statusText}`,
                                    }));
                                    return;
                                }

                                const profile = await response.json();
                                ws.send(JSON.stringify({
                                    type: 'resource',
                                    contents: [{
                                        uri: request.uri,
                                        text: JSON.stringify(profile),
                                    }],
                                }));
                            } catch (error) {
                                ws.send(JSON.stringify({
                                    type: 'error',
                                    message: error instanceof Error ? error.message : 'Unknown error',
                                }));
                            }
                        }
                    } else if (request.type === 'tool') {
                        if (request.name === 'spotify:create-playlist') {
                            const schema = z.object({
                                name: z.string(),
                                description: z.string().optional(),
                                public: z.boolean().optional(),
                            });

                            try {
                                const args = schema.parse(request.args);
                                const accessToken = await this.spotifyAuth.getValidAccessToken();
                                const userResponse = await fetch('https://api.spotify.com/v1/me', {
                                    headers: {
                                        'Authorization': `Bearer ${accessToken}`,
                                    },
                                });
                                
                                if (!userResponse.ok) {
                                    throw new Error(`Failed to get user profile: ${userResponse.statusText}`);
                                }
                                
                                const user = await userResponse.json();
                                
                                const response = await fetch(`https://api.spotify.com/v1/users/${user.id}/playlists`, {
                                    method: 'POST',
                                    headers: {
                                        'Authorization': `Bearer ${accessToken}`,
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({
                                        name: args.name,
                                        description: args.description,
                                        public: args.public ?? false,
                                    }),
                                });

                                if (!response.ok) {
                                    throw new Error(`Failed to create playlist: ${response.statusText}`);
                                }

                                const playlist = await response.json();
                                ws.send(JSON.stringify({
                                    type: 'tool',
                                    content: [{
                                        type: 'success',
                                        text: JSON.stringify(playlist),
                                    }],
                                }));
                            } catch (error) {
                                ws.send(JSON.stringify({
                                    type: 'tool',
                                    content: [{
                                        type: 'error',
                                        text: error instanceof Error ? error.message : 'Unknown error',
                                    }],
                                    isError: true,
                                }));
                            }
                        }
                    }
                } catch (error) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        message: error instanceof Error ? error.message : 'Unknown error',
                    }));
                }
            });

            ws.on('close', () => {
                console.log('Client disconnected');
            });
        });
    }

    public start(): Promise<void> {
        return new Promise((resolve) => {
            this.wss.on('listening', () => {
                console.log('Spotify MCP server started on ws://localhost:3001');
                resolve();
            });
        });
    }
} 