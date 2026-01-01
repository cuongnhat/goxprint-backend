FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application
COPY server.js ./

# Create data directories
RUN mkdir -p /app/data/drivers

# Environment variables
ENV NODE_ENV=production
ENV PORT=3001
ENV DATABASE_PATH=/app/data/goxprint.db

# Expose port
EXPOSE 3001

# Start server
CMD ["node", "server.js"]
