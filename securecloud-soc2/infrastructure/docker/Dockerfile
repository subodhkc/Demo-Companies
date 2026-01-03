# SecureCloud Platform - Production Dockerfile
# SOC 2 Control: CC6.8 (Malware Protection), CC5.2 (Technology Controls)
#
# Multi-stage build for security and optimization
# Base image: Node.js 20 Alpine (minimal attack surface)

# =============================================================================
# Stage 1: Dependencies
# =============================================================================
FROM node:20-alpine AS deps

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY backend/package*.json ./backend/
COPY frontend/package*.json ./frontend/

# Install dependencies with clean install
RUN npm ci --only=production && \
    npm cache clean --force

# =============================================================================
# Stage 2: Build Backend
# =============================================================================
FROM node:20-alpine AS build-backend

WORKDIR /app

# Copy dependencies
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/backend/node_modules ./backend/node_modules

# Copy source
COPY backend ./backend
COPY tsconfig.json ./

# Build
WORKDIR /app/backend
RUN npm run build

# =============================================================================
# Stage 3: Build Frontend
# =============================================================================
FROM node:20-alpine AS build-frontend

WORKDIR /app

# Copy dependencies
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/frontend/node_modules ./frontend/node_modules

# Copy source
COPY frontend ./frontend

# Build
WORKDIR /app/frontend
RUN npm run build

# =============================================================================
# Stage 4: Production Image
# =============================================================================
FROM node:20-alpine AS production

# Security labels
LABEL org.opencontainers.image.title="SecureCloud Platform"
LABEL org.opencontainers.image.description="SOC 2 Certified Cloud Platform"
LABEL org.opencontainers.image.vendor="SecureCloud Inc."
LABEL org.opencontainers.image.version="2.4.0"
LABEL security.soc2.compliant="true"

# Security: Install security updates
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
      dumb-init \
      curl \
    && rm -rf /var/cache/apk/*

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Create app directory
WORKDIR /app

# Copy production dependencies
COPY --from=deps --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=deps --chown=nodejs:nodejs /app/backend/node_modules ./backend/node_modules

# Copy built backend
COPY --from=build-backend --chown=nodejs:nodejs /app/backend/dist ./backend/dist
COPY --from=build-backend --chown=nodejs:nodejs /app/backend/package.json ./backend/

# Copy built frontend (for serving static files)
COPY --from=build-frontend --chown=nodejs:nodejs /app/frontend/dist ./frontend/dist

# Copy configuration
COPY --chown=nodejs:nodejs package.json ./

# Security: Set file permissions
RUN chmod -R 550 /app && \
    chmod -R 770 /app/backend/dist

# Security: Create log directory
RUN mkdir -p /var/log/securecloud && \
    chown -R nodejs:nodejs /var/log/securecloud

# Switch to non-root user
USER nodejs

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Health check - SOC 2 Control: A1.1
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Expose port
EXPOSE 3000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start application
CMD ["node", "backend/dist/index.js"]
