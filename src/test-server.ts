import express, { Request, Response } from 'express';
import { SpotifyApi } from '@spotify/web-api-ts-sdk';
import { config } from 'dotenv';
import { createSpotifyMcpServer } from './mcp/index.js';
import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { SpotifyMcpServer } from './mcp/spotify.js';
import WebSocket from 'ws';
import { SpotifyAuth } from './auth/spotify.js';

// Load environment variables
config();

const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, SPOTIFY_REDIRECT_URI } = process.env;

if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET || !SPOTIFY_REDIRECT_URI) {
    throw new Error('Missing required Spotify credentials in .env file');
}

// Ensure the redirect URI is properly formatted
const redirectUri = SPOTIFY_REDIRECT_URI.endsWith('/') 
    ? SPOTIFY_REDIRECT_URI.slice(0, -1) 
    : SPOTIFY_REDIRECT_URI;

console.log('Using redirect URI:', redirectUri);

const app = express();
app.use(cookieParser());
app.set('trust proxy', 1); // Trust the first proxy (Cloudflare)

let spotifyAuth: SpotifyAuth;

// Function to generate PKCE challenge
function generateCodeChallenge(verifier: string) {
    const base64hash = crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    return base64hash;
}

app.get('/', async (_req: Request, res: Response) => {
    const html = `
        <html>
            <body>
                <h1>Spotify MCP Test Server</h1>
                <button onclick="window.location.href='/login'">Login with Spotify</button>
                <hr>
                <h2>Test Actions</h2>
                <button onclick="testUserProfile()" ${!spotifyAuth ? 'disabled' : ''}>Test User Profile</button>
                <button onclick="testCreatePlaylist()" ${!spotifyAuth ? 'disabled' : ''}>Test Create Playlist</button>
                <pre id="result"></pre>
                <script>
                    async function testUserProfile() {
                        const response = await fetch('/test/profile');
                        const result = await response.text();
                        document.getElementById('result').textContent = result;
                    }
                    
                    async function testCreatePlaylist() {
                        const response = await fetch('/test/create-playlist', {
                            method: 'POST'
                        });
                        const result = await response.text();
                        document.getElementById('result').textContent = result;
                    }
                </script>
            </body>
        </html>
    `;
    res.send(html);
});

app.get('/login', async (_req: Request, res: Response) => {
    try {
        spotifyAuth = new SpotifyAuth();
        const { url, state } = spotifyAuth.generateAuthUrl();
        
        // Store code verifier in session (in a real app, use a proper session store)
        res.cookie('code_verifier', state, { httpOnly: true, secure: true });
        
        console.log('Authorization URL:', url);
        res.redirect(url);
    } catch (error) {
        console.error('Error in login:', error);
        res.status(500).send(`Error during authentication: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
});

app.get('/callback', async (req: Request, res: Response) => {
    try {
        const code = req.query.code as string;
        const state = req.query.state as string;
        const host = req.headers.host;

        if (!code) {
            throw new Error('No code provided');
        }

        const { accessToken } = await spotifyAuth.getAccessToken(code, state, host);
        res.redirect('/');
    } catch (error) {
        console.error('Error in callback:', error);
        res.status(500).send(`Error during authentication: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
});

app.get('/test/profile', async (_req: Request, res: Response) => {
    try {
        const ws = new WebSocket('ws://localhost:3001');
        ws.on('message', (data) => {
            const response = JSON.parse(data.toString());
            res.send(JSON.stringify(response, null, 2));
            ws.close();
        });
        ws.on('open', () => {
            ws.send(JSON.stringify({
                type: 'resource',
                uri: 'spotify:user:profile'
            }));
        });
    } catch (error) {
        res.status(500).send(error instanceof Error ? error.message : 'Unknown error');
    }
});

app.post('/test/create-playlist', async (_req: Request, res: Response) => {
    try {
        const ws = new WebSocket('ws://localhost:3001');
        ws.on('message', (data) => {
            const response = JSON.parse(data.toString());
            res.send(JSON.stringify(response, null, 2));
            ws.close();
        });
        ws.on('open', () => {
            ws.send(JSON.stringify({
                type: 'tool',
                name: 'spotify:create-playlist',
                args: {
                    name: 'Test Playlist',
                    description: 'Created via MCP server test',
                    public: false
                }
            }));
        });
    } catch (error) {
        res.status(500).send(error instanceof Error ? error.message : 'Unknown error');
    }
});

const server = https.createServer({
    key: fs.readFileSync(process.env.SSL_KEY_PATH || path.join(process.cwd(), 'certs', 'localhost-key.pem')),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH || path.join(process.cwd(), 'certs', 'localhost.pem'))
}, app);

const port = process.env.PORT || 3000;
server.listen(port, () => {
    console.log(`Test server running at https://localhost:${port}`);
    console.log(`Accessible via Cloudflare tunnel at: ${redirectUri.replace('/callback', '')}`);
});

async function main() {
    try {
        const server = new SpotifyMcpServer();
        await server.start();
        console.log('Server started on ws://localhost:3001');
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

main(); 