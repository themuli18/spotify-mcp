import { config } from 'dotenv';
import https from 'https';
import { SpotifyAuth } from './auth/spotify.js';
import fs from 'fs';
import express from 'express';
import cookieParser from 'cookie-parser';

export class AuthServer {
    private server: https.Server;
    private spotifyAuth: SpotifyAuth;
    private port: number;

    constructor(spotifyAuth: SpotifyAuth) {
        this.spotifyAuth = spotifyAuth;
        this.port = parseInt(process.env.PORT || '3000', 10);

        // Read SSL certificates
        const key = fs.readFileSync(process.env.SSL_KEY_PATH || '');
        const cert = fs.readFileSync(process.env.SSL_CERT_PATH || '');

        this.server = https.createServer({
            key,
            cert,
            // More permissive SSL options for development
            minVersion: 'TLSv1.2',
            rejectUnauthorized: false,
            requestCert: false
        }, async (req, res) => {
            // Log incoming request
            console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - Host: ${req.headers.host}`);
            
            // Set CORS headers
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

            if (req.method === 'OPTIONS') {
                res.writeHead(200);
                res.end();
                return;
            }

            // Handle routes
            try {
                if (req.url === '/' || req.url === '') {
                    console.log('Serving homepage');
                    // Serve the homepage
                    const html = `
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="UTF-8">
                            <title>Spotify MCP Server</title>
                            <style>
                                body {
                                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                                    max-width: 800px;
                                    margin: 0 auto;
                                    padding: 2rem;
                                    line-height: 1.6;
                                }
                                .button {
                                    display: inline-block;
                                    padding: 10px 20px;
                                    background-color: #1DB954;
                                    color: white;
                                    text-decoration: none;
                                    border-radius: 20px;
                                    margin: 10px 0;
                                }
                                .button:hover {
                                    background-color: #1ed760;
                                }
                            </style>
                        </head>
                        <body>
                            <h1>🎵 Spotify MCP Server</h1>
                            <p>Welcome to the Spotify MCP (Model Context Protocol) Server. This server provides a bridge between AI models and the Spotify API.</p>
                            
                            <h2>Getting Started</h2>
                            <p>To use the Spotify MCP Server, you'll need to authenticate with your Spotify account first.</p>
                            
                            <a href="/login" class="button">Login with Spotify</a>
                            
                            <h2>Available Features</h2>
                            <ul>
                                <li>View your Spotify profile</li>
                                <li>Create and manage playlists</li>
                                <li>Access your saved tracks</li>
                            </ul>
                            
                            <p><small>Running on port ${this.port}</small></p>
                        </body>
                        </html>
                    `;
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(html);
                }
                else if (req.url?.startsWith('/login')) {
                    const host = req.headers.host;
                    const { url, state } = this.spotifyAuth.generateAuthUrl(host);
                    res.writeHead(302, { Location: url });
                    res.end();
                }
                else if (req.url?.startsWith('/callback')) {
                    const host = req.headers.host;
                    const url = new URL(req.url, `https://${host}`);
                    const code = url.searchParams.get('code');
                    const state = url.searchParams.get('state');

                    if (!code || !state) {
                        throw new Error('Missing code or state parameter');
                    }

                    const { accessToken, refreshToken, expiresIn } = await this.spotifyAuth.getAccessToken(code, state, host);

                    // Show a success page
                    const html = `
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="UTF-8">
                            <title>Authentication Successful</title>
                            <style>
                                body {
                                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                                    max-width: 800px;
                                    margin: 0 auto;
                                    padding: 2rem;
                                    line-height: 1.6;
                                }
                                .success {
                                    color: #1DB954;
                                }
                            </style>
                        </head>
                        <body>
                            <h1 class="success">✓ Authentication Successful!</h1>
                            <p>You have successfully authenticated with Spotify. You can now close this window and return to using the MCP server.</p>
                            <p><a href="/">Return to homepage</a></p>
                        </body>
                        </html>
                    `;
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(html);
                }
                else {
                    res.writeHead(404);
                    res.end('Not found');
                }
            } catch (error) {
                console.error('Error handling request:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error instanceof Error ? error.message : 'Internal server error' }));
            }
        });
    }

    start(): Promise<void> {
        return new Promise((resolve) => {
            this.server.listen(this.port, () => {
                console.log(`Auth server listening on port ${this.port}`);
                resolve();
            });
        });
    }

    stop(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.server.close((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }
} 