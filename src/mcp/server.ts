import { z } from 'zod';

export type ResourceHandler = (uri: string) => Promise<{
    contents: Array<{
        uri: string;
        text: string;
    }>;
}>;

export type ToolHandler = (args: any) => Promise<{
    content: Array<{
        type: string;
        text: string;
    }>;
    isError?: boolean;
}>;

export class McpServer {
    private resources: Map<string, ResourceHandler> = new Map();
    private tools: Map<string, { schema: z.ZodType<any>; handler: ToolHandler }> = new Map();

    constructor(private config: { name: string; version: string }) {}

    resource(name: string, uri: string, handler: ResourceHandler) {
        this.resources.set(name, handler);
    }

    tool(name: string, description: string, schema: z.ZodType<any>, handler: ToolHandler) {
        this.tools.set(name, { schema, handler });
    }

    async handleResource(name: string, uri: string) {
        const handler = this.resources.get(name);
        if (!handler) {
            throw new Error(`Resource ${name} not found`);
        }
        return handler(uri);
    }

    async handleTool(name: string, args: any) {
        const tool = this.tools.get(name);
        if (!tool) {
            throw new Error(`Tool ${name} not found`);
        }
        const validatedArgs = tool.schema.parse(args);
        return tool.handler(validatedArgs);
    }
} 