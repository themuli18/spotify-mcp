declare module '@modelcontextprotocol/sdk/dist/esm/server.js' {
    export class McpServer {
        constructor(name: string, version: string);
        addTransport(transport: any): void;
        resource(uri: string, callback: (uri: string) => Promise<any>): void;
        tool(name: string, schema: any, callback: (args: any) => Promise<any>): void;
        start(): Promise<void>;
    }
}

declare module '@modelcontextprotocol/sdk/dist/esm/server/websocket.js' {
    export class WebSocketServerTransport {
        constructor(options: { port: number });
    }
}

declare module '@modelcontextprotocol/sdk/dist/esm/types.js' {
    export type ResourceUri = string;
    export type ToolArgs = any;
} 