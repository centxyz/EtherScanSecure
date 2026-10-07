const express = require('express'); const cors = require('cors'); const morgan = require('morgan'); const { EtherScanSecureService, ScanError } = require('./services/etherscansecure-service');
function parseRpcUrls(value) { if (!value) return {}; let parsed; try { parsed = JSON.parse(value); } catch { throw new Error('RPC_URLS must be valid JSON'); } for (const url of Object.values(parsed)) if (typeof url !== 'string' || !/^https?:\/\//.test(url)) throw new Error('RPC_URLS values must be HTTP(S) URLs'); return parsed; }
class Server {
  constructor({ port = 3000, service, corsOrigin = false } = {}) { this.port = Number(port); this.service = service || new EtherScanSecureService({ rpcUrls: parseRpcUrls(process.env.RPC_URLS) }); this.app = express(); this.app.disable('x-powered-by'); this.app.use(cors({ origin: corsOrigin || false })); this.app.use(express.json({ limit: '32kb' })); this.app.use(morgan('combined')); this.routes(); }
  routes() {
    this.app.get('/health', (_req, res) => res.json({ status: 'healthy', service: 'EtherScanSecure', chains: this.service.listChains() }));
    this.app.post('/api/v1/scan/transaction', (req, res, next) => { try { res.json(this.service.scanTransaction(req.body)); } catch (error) { next(error); } });
    this.app.get('/api/v1/scan/address/:chain/:address', async (req, res, next) => { try { res.json(await this.service.scanAddress(req.params.chain, req.params.address)); } catch (error) { next(error); } });
    this.app.use((_req, res) => res.status(404).json({ error: 'Route not found', code: 'NOT_FOUND' }));
    this.app.use((error, _req, res, _next) => res.status(error instanceof ScanError ? error.status : 500).json({ error: error.message, code: error.code || 'INTERNAL' }));
  }
  start() { this.httpServer = this.app.listen(this.port, () => console.log(`EtherScanSecure listening on ${this.port}`)); return this.httpServer; }
}
if (require.main === module) new Server({ port: process.env.PORT || 3000, corsOrigin: process.env.CORS_ORIGIN || false }).start();
module.exports = { Server, parseRpcUrls };
