# Spotify MCP Worker

## MCP Durable Object Pattern: Learnings from Math MCP Worker

### Why This Pattern?
- Ensures robust tool discovery and compatibility with Claude and other MCP clients.
- Uses the official `McpAgent`/`McpServer` pattern from the Model Context Protocol SDK.
- Durable Object is required for session management and tool registration.

### Key Steps

1. **Use the Official MCP Agent Pattern**
   - Extend `McpAgent` and register tools on a `McpServer` instance.
   - Export your agent class as `McpAgent` for Durable Object binding.

2. **Export the Durable Object Class**
   ```ts
   export { MyMCP as McpAgent };
   ```

3. **Update `wrangler.toml`**
   - Add Durable Object binding and migration:
   ```toml
   [durable_objects]
   bindings = [
     { name = "MCP_OBJECT", class_name = "McpAgent" }
   ]

   [[migrations]]
   tag = "v1"
   new_sqlite_classes = ["McpAgent"]
   ```
   - Set `compatibility_date` to at least `2024-09-23` and add `compatibility_flags = ["nodejs_compat"]`.

4. **Deploy and Test**
   - Run `npx wrangler deploy`.
   - Use `npx wrangler tail --format=pretty` to observe logs.
   - Confirm tool discovery and tool calls work with Claude.

---

## Example: Minimal MCP Agent Pattern

```ts
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

interface Env {}

export class MyMCP extends McpAgent<Env, Record<string, never>, Record<string, never>> {
    server = new McpServer({
        name: "Simple Math Calculator",
        version: "1.0.0",
    });

    async init() {
        this.server.tool(
            "calculate",
            {
                operation: z.enum(["add", "subtract", "multiply", "divide"]),
                a: z.number(),
                b: z.number(),
            },
            async ({ operation, a, b }) => {
                let result: number;
                switch (operation) {
                    case "add": result = a + b; break;
                    case "subtract": result = a - b; break;
                    case "multiply": result = a * b; break;
                    case "divide":
                        if (b === 0) return { content: [{ type: "text", text: "Error: Cannot divide by zero" }] };
                        result = a / b; break;
                }
                return { content: [{ type: "text", text: String(result) }] };
            }
        );
    }
}

export { MyMCP as McpAgent };

export default {
    fetch(request: Request, env: Env, ctx: ExecutionContext) {
        const url = new URL(request.url);
        if (url.pathname === "/sse" || url.pathname === "/sse/message") {
            return MyMCP.serveSSE("/sse").fetch(request, env, ctx);
        }
        if (url.pathname === "/mcp") {
            return MyMCP.serve("/mcp").fetch(request, env, ctx);
        }
        return new Response("Not found", { status: 404 });
    },
};
```

---

## Next Steps for Spotify MCP Server

- Refactor the Spotify MCP server to use this pattern.
- Ensure Durable Object binding and migration are present in `wrangler.toml`.
- Export the agent class as `McpAgent`.
- Deploy and verify tool discovery with Claude.
