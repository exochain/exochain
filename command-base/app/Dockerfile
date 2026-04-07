FROM node:20-alpine

# Install curl for health checks and API fallback
RUN apk add --no-cache curl

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

# Create symlink for claude CLI (mounted via docker-compose volume)
RUN ln -sf /usr/local/lib/claude-code/cli.js /usr/local/bin/claude && \
    chmod +x /usr/local/bin/claude 2>/dev/null || true

# Create entrypoint script that sets up claude config before starting
RUN printf '#!/bin/sh\n\
# Copy host .claude.json if it exists and we do not have one\n\
if [ ! -f /root/.claude.json ] && [ -f /host-home/.claude.json ]; then\n\
  cp /host-home/.claude.json /root/.claude.json\n\
  echo "[Startup] Copied claude config from host"\n\
fi\n\
# Restore from backup if .claude.json still missing\n\
if [ ! -f /root/.claude.json ] && [ -d /root/.claude/backups ]; then\n\
  LATEST=$(ls -t /root/.claude/backups/.claude.json.backup.* 2>/dev/null | head -1)\n\
  if [ -n "$LATEST" ]; then\n\
    cp "$LATEST" /root/.claude.json\n\
    echo "[Startup] Restored claude config from backup: $LATEST"\n\
  fi\n\
fi\n\
exec node server.js\n' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 3000

CMD ["/app/entrypoint.sh"]
