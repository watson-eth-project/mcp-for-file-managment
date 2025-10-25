#!/bin/bash

# Start the MCP Vulnerability Data System with OAuth authentication
echo "🚀 Starting MCP Vulnerability Data System with OAuth authentication..."

# Start 1MCP agent with HTTP transport and OAuth enabled
# Use local .1mcprc configuration file
cd agent
echo "Starting 1MCP agent on http://127.0.0.1:3050 with OAuth authentication...--enable-auth "
echo "Using configuration: ../.1mcprc"
pnpm start --transport http --port 3050 --host 127.0.0.1 --log-level info --config ../.1mcprc
