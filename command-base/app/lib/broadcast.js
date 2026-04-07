'use strict';

const { WebSocketServer } = require('ws');

let wss = null;
const wsClients = new Set();

function setupWebSocket(server) {
  wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws) => {
    wsClients.add(ws);
    ws.on('close', () => wsClients.delete(ws));
    ws.on('error', () => wsClients.delete(ws));
  });

  return wss;
}

function broadcast(eventType, payload) {
  const message = JSON.stringify({ type: eventType, data: payload, timestamp: new Date().toISOString() });
  for (const client of wsClients) {
    if (client.readyState === 1) { // OPEN
      client.send(message);
    }
  }
}

function getWss() { return wss; }
function getWsClients() { return wsClients; }

module.exports = { setupWebSocket, broadcast, getWss, getWsClients };
