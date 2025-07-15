import { WebSocket, WebSocketServer } from 'ws';
import { SpotifyMcpServer } from './spotify.js';

export function createSpotifyMcpServer() {
    return new SpotifyMcpServer();
}

export * from './server.js';
export * from './spotify.js'; 