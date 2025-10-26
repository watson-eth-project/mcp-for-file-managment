# Use Node.js 20 as base image for the 1MCP agent
FROM node:20-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    pandoc \
    texlive-latex-base \
    texlive-fonts-recommended \
    texlive-latex-extra \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Go (auto-detect architecture for multi-platform builds)
ARG TARGETARCH=amd64
RUN case ${TARGETARCH} in \
    amd64) ARCH=amd64 ;; \
    arm64) ARCH=arm64 ;; \
    arm) ARCH=armv6l ;; \
    *) ARCH=amd64 ;; \
    esac && \
    wget "https://go.dev/dl/go1.23.2.linux-${ARCH}.tar.gz" && \
    tar -C /usr/local -xzf "go1.23.2.linux-${ARCH}.tar.gz" && \
    rm "go1.23.2.linux-${ARCH}.tar.gz"

# Install uv package manager for Python
RUN pip3 install --break-system-packages uv

# Add Go to PATH
ENV PATH="/usr/local/go/bin:${PATH}"

# Copy Python project files
COPY pyproject.toml uv.lock ./
COPY server.py ./
COPY README.md ./
COPY .1mcprc.docker ./

# Install Python dependencies
RUN uv sync --frozen

# Copy all MCP servers
COPY fetch-mcp/ ./fetch-mcp/
COPY gitingest-mcp/ ./gitingest-mcp/
COPY mcp-pandoc/ ./mcp-pandoc/
COPY mcp-filesystem-server/ ./mcp-filesystem-server/
COPY mcp-interpreter-server/ ./mcp-interpreter-server/
COPY parse-pdf/ ./parse-pdf/

# Install dependencies for each MCP server
WORKDIR /app/fetch-mcp
RUN npm install && \
    npm install -g typescript && \
    npm run build

WORKDIR /app/gitingest-mcp
RUN uv sync --frozen

WORKDIR /app/mcp-pandoc
RUN uv sync --frozen

WORKDIR /app/mcp-interpreter-server
RUN uv sync --frozen

WORKDIR /app/parse-pdf
RUN uv sync --frozen

# Copy Node.js agent
WORKDIR /app
COPY agent/ ./agent/

# Install Node.js dependencies
WORKDIR /app/agent
RUN npm install -g pnpm && \
    pnpm install && \
    pnpm build

# Go back to app root
WORKDIR /app

# Build Go filesystem server (after all copying is done)
WORKDIR /app/mcp-filesystem-server
RUN CGO_ENABLED=0 GOOS=linux go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o mcp-filesystem-server main.go
RUN chmod +x mcp-filesystem-server
RUN ls -la mcp-filesystem-server

# Go back to app root
WORKDIR /app

# Create necessary directories
RUN mkdir -p /tmp/mcp_cache /tmp/vuln_data

# Create a proper Git environment for gitingest to work with
RUN cd /app && \
    git init . && \
    git config user.name "Docker User" && \
    git config user.email "docker@example.com" && \
    git config core.preloadindex false && \
    git config core.fscache false && \
    git config gc.auto 0 && \
    git config submodule.recurse false && \
    git config submodule.active false && \
    echo "# Docker Git Repository" > README.md && \
    git add README.md && \
    git commit -m "Initial commit" || true

# Expose ports
# 3050 for 1MCP agent, 8000 for Python server
EXPOSE 3050 8000

# Set environment variables
ENV PYTHONPATH=/app
ENV NODE_ENV=production
ENV MCP_CACHE_DIR=/tmp/mcp_cache
ENV VULN_DATA_DIR=/tmp/vuln_data

# Create startup script with proper error handling
RUN printf '#!/bin/bash\n\
set -e\n\
echo "Starting MCP Vulnerability Data System..."\n\
echo "Config file location: /app/.1mcprc.docker"\n\
if [ -f /app/.1mcprc.docker ]; then\n\
    echo "✓ Config file found"\n\
else\n\
    echo "✗ Config file NOT found!"\n\
    exit 1\n\
fi\n\
echo "Starting Python server..."\n\
cd /app && uv run server.py &\n\
PYTHON_PID=$!\n\
sleep 2\n\
echo "Starting 1MCP agent..."\n\
cd /app/agent && pnpm start --transport http --port 3050 --host 0.0.0.0 --log-level info --config /app/.1mcprc.docker &\n\
NODE_PID=$!\n\
cleanup() {\n\
    echo "Shutting down..."\n\
    kill $PYTHON_PID $NODE_PID 2>/dev/null || true\n\
    exit 0\n\
}\n\
trap cleanup SIGTERM SIGINT\n\
wait $PYTHON_PID $NODE_PID\n' > /app/start.sh && chmod +x /app/start.sh

# Set working directory for runtime
WORKDIR /app

# Default command - use exec form for better signal handling
CMD ["/bin/bash", "/app/start.sh"]
