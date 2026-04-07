FROM node:20-bookworm-slim

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /worker

COPY package*.json ./
RUN npm install --production

COPY . .

CMD ["node", "index.js"]
