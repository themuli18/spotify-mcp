import { WebSocket } from 'ws';
import { createSpotifyMcpServer } from './mcp/index.js';

async function runTests() {
    const server = createSpotifyMcpServer();
    await server.start();

    const ws = new WebSocket('ws://localhost:3001');

    await new Promise<void>((resolve) => {
        ws.on('open', resolve);
    });

    // Test user profile resource
    ws.send(JSON.stringify({
        type: 'resource',
        uri: 'spotify:user:profile'
    }));

    const profileResult = await new Promise((resolve) => {
        ws.once('message', (data) => {
            resolve(JSON.parse(data.toString()));
        });
    });

    console.log('Profile result:', profileResult);

    // Test create playlist tool
    ws.send(JSON.stringify({
        type: 'tool',
        name: 'spotify:create-playlist',
        args: {
            name: 'Test Playlist',
            description: 'Created by test',
            public: false
        }
    }));

    const playlistResult = await new Promise((resolve) => {
        ws.once('message', (data) => {
            resolve(JSON.parse(data.toString()));
        });
    });

    console.log('Playlist result:', playlistResult);

    ws.close();
}

runTests().catch(console.error); 