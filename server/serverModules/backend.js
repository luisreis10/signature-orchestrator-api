// backend.js

// ===== Imports and Core Setup =====
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Custom modules for logging and OTCS/Adobe Sign token/file ops
const logger = require('../serverModules/logger');
const { setToken, ensureToken } = require('./tokenManager');
const { downloadNode, uploadToFolder, sendOnWorkflow } = require('./otcsManager');

const app = express();
const PORT = process.env.PORT || 3000;

/* 
  === Folders and File System Prep ===
  Prepares working folders both for dev/prod and loads/saves the agreement mapping file.
*/
if (process.env.NODE_ENV === "production" && !fs.existsSync('/tmp')) {
  fs.mkdirSync('/tmp', { recursive: true });
}

const INP_ROOT = process.env.NODE_ENV === "production"
  ? "/tmp/inprocess"
  : path.join(__dirname, '../inprocess');
if (!fs.existsSync(INP_ROOT)) fs.mkdirSync(INP_ROOT, { recursive: true });

const MAP_FILE = process.env.NODE_ENV === "production"
  ? "/tmp/agreements.json"
  : path.join(__dirname, 'agreements.json');
// Agreements map: links AdobeSign agreements to OTCS nodes/workflows/etc
let MAP = fs.existsSync(MAP_FILE) ? JSON.parse(fs.readFileSync(MAP_FILE, 'utf8')) : {};
function saveMap() { fs.writeFileSync(MAP_FILE, JSON.stringify(MAP, null, 2)); }

/*
  === Adobe Sign / API Config ===
  Sets up credentials and API endpoints for OAuth and REST calls.
*/
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const NGROK_HOST = 'https://signature-orchestrator-api-2gim.onrender.com';
const REDIRECT_URI = `${NGROK_HOST}/admin/callback`;
const API_BASE = 'https://api.eu1.adobesign.com';
const AUTH_BASE = 'https://secure.eu1.adobesign.com';
const crypto = require('crypto');

// === Admin Routes for OAuth Flow ===
// Route: Login with Adobe Sign - redirects to consent page with needed scopes
app.get('/admin/login', (_, res) => {
  const SCOPES = [
    'agreement_send:account',
    'agreement_write:account',
    'agreement_read:account',
    'account_read:account',
    'account_write:account',
    'user_login:account'
  ];

  // monta o scope no formato aceito: separados por "+"
  const scopeParam = SCOPES.join('+');

  // constroi a URL final
  const url = `${AUTH_BASE}/public/oauth/v2?` +
    `response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${scopeParam}`;

  // loga no console pra debug
  console.log('[Adobe OAuth URL]', url);

  res.redirect(url);
});




// Route: OAuth2 callback - exchanges code for tokens and saves them locally
app.get('/admin/callback', async (req, res) => {
  const { code } = req.query;
  try {
    const r = await axios.post(`${API_BASE}/oauth/v2/token`,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    setToken(r.data.access_token, r.data.expires_in, r.data.refresh_token);
    logger.info('Token saved successfully');
    res.send('<h1>Token saved</h1>');
  } catch (e) {
    const msg = e.response?.data?.error_description || e.message;
    logger.error(`OAUTH CALLBACK ERROR: ${msg}`);
    res.status(500).send(`<pre>${msg}</pre>`);
  }
});

// Simple healthcheck route
app.get('/health', (_, res) => res.status(200).json({ status: 'ok' }));

/*
  === Global Middlewares ===
  - CORS
  - JSON and URLENCODED body parsers
  - Route logger with grouping for easier CLI/Log reading
*/
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../../static')));
let lastRouteGroup = null;

app.use((req, _, next) => {
  const currentGroup = `${req.method} ${req.path}`;
  if (lastRouteGroup && lastRouteGroup !== currentGroup) console.log('');
  lastRouteGroup = currentGroup;
  //logger.info(`${req.method} ${req.originalUrl}`);

  // Log POST /start with extra context (who/what is being signed)
  if (req.method === 'POST' && req.path === '/start') {
    const { userEmail1, userEmail2, nodeId, attachId, docName } = req.body;
    const emails = [userEmail1, userEmail2].filter(Boolean).join(', ');
    logger.info(
      `Signature request initiated\n` +
      `  → Document: ${decodeURIComponent(docName || '?')}\n` +
      `  → Node ID: ${nodeId}\n` +
      `  → Target Folder ID: ${attachId}\n` +
      `  → Recipients: ${emails}`
    );
  }
  next();
});

/*
  === HMAC Auth Endpoints ===
  - /auth GET: Used by frontend to get timestamp and HMAC, with basic auth
  - verifySignature middleware: Used by POST /start to enforce signed requests and freshness window
*/
// Endpoint: Issues timestamp+signature to front
app.get('/auth', basicAuth, (req, res) => {
  const timestamp = Date.now().toString();
  const hmac = crypto
    .createHmac('sha256', process.env.SIGNATURE_SECRET)
    .update(timestamp)
    .digest('hex');
  res.json({ timestamp, signature: hmac });
});

// Middleware: Verifies timestamp+HMAC in sensitive requests (e.g., /start)
function verifySignature(req, res, next) {
  const { signature, timestamp } = req.body;
  if (!signature || !timestamp) {
    return res.status(401).json({ error: "Missing signature or timestamp." });
  }
  if (!/^[a-f0-9]{64}$/i.test(signature)) {
    return res.status(400).json({ error: "Malformed signature." });
  }
  // Only accept requests within 2 minutes of the signature
  const age = Math.abs(Date.now() - Number(timestamp));
  if (age > 2 * 60 * 1000) {
    return res.status(403).json({ error: "Timestamp expired." });
  }
  const expected = crypto
    .createHmac('sha256', process.env.SIGNATURE_SECRET)
    .update(timestamp)
    .digest();
  const received = Buffer.from(signature, 'hex');
  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(expected, received)
  ) {
    return res.status(403).json({ error: "Invalid signature." });
  }
  next();
}

/*
  === Main Signature Workflow (/start) ===
  - Receives sign request, checks for recent duplicate
  - Downloads file from OTCS, uploads to Adobe, creates agreement, logs locally
  - Optionally triggers workflow movement on OTCS in background
*/
app.post('/start', verifySignature, async (req, res) => {
  const { userEmail1, userEmail2, nodeId, attachId, workflowId, subworkflowId, taskId } = req.body;
  const emails = [userEmail1, userEmail2]
    .filter(Boolean).flatMap(e => e.split(/[;,]+/)).map(e => e.trim()).filter(e => e.includes('@'));
  if (!emails.length || !nodeId) return res.status(400).json({ error: 'Node ID and Email are mandatory.' });
  if (!attachId || isNaN(+attachId)) return res.status(400).json({ error: 'attachId is mandatory.' });

  // Prevent duplicate submissions within threshold window (per doc/recipients)
  const now = Date.now();
  const threshold = 15 * 60 * 1000; // 15 min
  const newKey = [...emails].sort().join('|');
  const duplicate = Object.values(MAP).find(info => {
    if (String(info.nodeId) !== String(nodeId)) return false;
    if (!Array.isArray(info.emails) || info.emails.length !== emails.length) return false;
    const infoKey = [...info.emails].sort().join('|');
    if (infoKey !== newKey) return false;
    if (!info.createdAt) return false;
    return now - new Date(info.createdAt).getTime() < threshold;
  });
  if (duplicate) {
    return res.status(409).json({ error: 'El documento ya he sido enviado recientemente a este destinatario.' });
  }

  let token;
  try {
    token = await ensureToken();
  } catch {
    return res.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  try {
    // Download PDF from OTCS
    const original = await downloadNode(nodeId);
    const docName = req.body.docName?.trim();
    const fileName = docName;
    const filePath = path.join(INP_ROOT, fileName);
    fs.writeFileSync(filePath, original);

    // Upload PDF to Adobe Sign (as transient doc)
    const fd = new FormData();
    fd.append('File', fs.createReadStream(filePath), { filename: fileName, contentType: 'application/pdf' });
    const up = await axios.post(`${API_BASE}/api/rest/v6/transientDocuments`, fd,
      { headers: { Authorization: `Bearer ${token}`, ...fd.getHeaders() } });

    // Create agreement (envelope) on Adobe Sign
    const ag = await axios.post(`${API_BASE}/api/rest/v6/agreements`, {
      name: `Documento ${fileName}`,
      fileInfos: [{ transientDocumentId: up.data.transientDocumentId }],
      participantSetsInfo: emails.map(email => ({ role: 'SIGNER', order: 1, memberInfos: [{ email }] })),
      signatureType: 'ESIGN', state: 'IN_PROCESS'
    }, { headers: { Authorization: `Bearer ${token}` } });

    // Store agreement metadata locally (for later automation)
    MAP[ag.data.id] = {
      nodeId: String(nodeId),
      attachId: String(attachId),
      fileName,
      workflowId: String(workflowId || ''),
      subworkflowId: String(subworkflowId || workflowId || ''),
      sendonDone: false,
      emails,
      createdAt: new Date().toISOString()
    };
    saveMap();

    logger.info(`Signature requested: ${ag.data.id}`);

    // Trigger sendOnWorkflow in background (do not block client)
    if (workflowId) {
      sendOnWorkflow({
        workflowId,
        subworkflowId: subworkflowId || workflowId,
        taskId: taskId || 2,
        comment: 'Documento enviado para assinatura – etapa automatizada'
      }).then(() => {
        logger.info(`SendOn automático realizado para workflow ${workflowId}`);
      }).catch(e => {
        logger.error(`Falha no SendOn automático: ${e.message} | OTCS: ${JSON.stringify(e.response?.data)}`);
      });
    }

    // Reply to frontend: agreement created
    res.json({ message: `Signature requested. ID: ${ag.data.id}` });

  } catch (e) {
    const raw = e.response?.data;
    const errorMsg = Buffer.isBuffer(raw) ? raw.toString() : JSON.stringify(raw || e.message);
    logger.error(`[START ERROR] ${errorMsg}`);
    res.status(500).json({ error: raw || e.message });
  }
});

// Logs Streaming route
app.get('/logs/stream', basicAuth, (req, res) => {
  const logFilePath = process.env.NODE_ENV === 'production'
    ? '/tmp/audit.log'
    : path.join(__dirname, '../logs/audit.log');

  if (!fs.existsSync(logFilePath)) {
    return res.status(404).send('Log file not found.');
  }

  res.writeHead(200, {
    'Content-Type':    'text/event-stream',
    'Cache-Control':   'no-cache',
    'Connection':      'keep-alive'
  });

  // 1) envia todo o conteúdo atual logo que o cliente conecta
  const all = fs.readFileSync(logFilePath, 'utf8')
                .split('\n')
                .filter(l => l.trim() !== '');
  all.forEach(line => res.write(`data: ${line}\n\n`));

let lastLineCount = all.length;

const watcher = fs.watch(logFilePath, { encoding: 'utf8' }, (evtType) => {
  if (evtType !== 'change') return;

  const lines = fs.readFileSync(logFilePath, 'utf8')
                  .trim()
                  .split('\n');

  const newLines = lines.slice(lastLineCount);
  newLines.forEach(line => {
    if (line.trim()) res.write(`data: ${line}\n\n`);
  });

  lastLineCount = lines.length;
});

  req.on('close', () => watcher.close());
});


/*
  === Workflow Advancement Handler ===
  - Used to send tasks forward in the OTCS workflow after signature events
*/
async function triggerDisposition(agreementId, disposition) {
  const info = MAP[agreementId];
  if (!info || !info.workflowId) {
    logger.warn(`No workflowId stored for ${agreementId}; disposition skipped`);
    return;
  }

  try {
    await sendOnWorkflow({
      workflowId: info.workflowId,
      subworkflowId: info.subworkflowId || info.workflowId,
      taskId: 3,
      disposition,
      comment: `Documento ${disposition.toLowerCase()} via webhook`
    });
    info.sendonDone = true;
    saveMap();
    logger.info(`SendOn task 3 (${disposition}) done for workflow ${info.workflowId}`);
  } catch (e) {
    logger.error(`SendOn task 3 failed: ${e.message}`);
  }
}

/*
  === Adobe Sign Webhook Handshake and Event Handling ===
  - HEAD/GET for webhook setup/validation
  - POST for processing all Adobe Sign event notifications
*/
// HEAD: Required by Adobe for webhook validation handshake
app.head('/webhook', (req, res) => {
  res.setHeader('X-AdobeSign-ClientId', CLIENT_ID);
  res.setHeader('Content-Type', 'application/json');
  res.status(200).end(); // HEAD never returns a body
});

// GET: Webhook challenge/handshake
app.get('/webhook', (req, res) => {
  const cid = req.headers['x-adobesign-clientid'] || CLIENT_ID;
  if (req.query.challenge) {
    res.setHeader('X-AdobeSign-ClientId', cid);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(200).send(`${req.query.challenge}`);
  }
  res.setHeader('X-AdobeSign-ClientId', cid);
  res.setHeader('Content-Type', 'application/json');
  return res.status(200).json({ status: 'pong' });
});

// POST: Receives all webhook events from Adobe Sign (signature complete, rejected, etc)
app.post('/webhook', express.json({ limit: '10mb' }), async (req, res) => {
  const cid = req.headers['x-adobesign-clientid'] ||
    req.headers['x-adobesign-client-id'] ||
    CLIENT_ID;
  res.setHeader('X-AdobeSign-ClientId', cid);

  // Parse the body, even if stringified JSON (defensive)
  let payload = {};
  try {
    payload = typeof req.body === 'object' ? req.body : JSON.parse(req.body.toString());
  } catch (err) {
    logger.error(`Webhook parse error: ${err.message}`);
    return res.status(400).send('Invalid webhook payload');
  }
  // Log first 4KB of webhook for diagnostics
  //const short = JSON.stringify(payload).slice(0, 4000);
  //logger.info(`Webhook raw (trunc): ${short}${payload.length > 4000 ? '…' : ''}`);

  // Parse core event info from Adobe payload (defensive for different schemas)
  const agreementId = payload.event?.agreementId || payload.agreement?.id || payload.agreementId;
  const evt = payload.event?.eventType || payload.event || payload.type || 'UNKNOWN_EVENT';
  const participant = payload.event?.participantUserEmail || payload.participantUserEmail || 'unknown';
  const timestamp = payload.event?.eventDate || new Date().toISOString();

  logger.info(
    `Webhook received\n` +
    `  → Event: ${evt}\n` +
    `  → Agreement ID: ${agreementId}\n` +
    `  → Participant: ${participant}\n` +
    `  → Date: ${timestamp}`
  );

  // PDF/complete events: download signed PDF, update OTCS, move workflow
  const info = MAP[agreementId];
  const PDF_EVENTS = [
    'DOCUMENT_SIGNED', 'PARTICIPANT_COMPLETED', 'PARTICIPANT_SIGNED',
    'AGREEMENT_COMPLETED', 'AGREEMENT_SIGNED', 'AGREEMENT_ACTION_COMPLETED',
    'AGREEMENT_WORKFLOW_COMPLETED', 'AGREEMENT_REJECTED'
  ];
  const FINAL_OK_EVENTS = [
    'AGREEMENT_COMPLETED',
    'AGREEMENT_SIGNED',
    'AGREEMENT_WORKFLOW_COMPLETED'
  ];

  if (PDF_EVENTS.includes(evt)) {
    try {
      await overwritePdf(agreementId);
      if (!info.sendonDone) {
        if (evt === 'AGREEMENT_REJECTED') {
          await triggerDisposition(agreementId, 'Rechazado');
        } else if (FINAL_OK_EVENTS.includes(evt)) {
          await triggerDisposition(agreementId, 'Firmado');
        }
      }
    } catch (err) {
      logger.error(`Erro durante PDF+SendOn: ${err.message}`);
    }
    return res.status(200).send('OK');
  }

  res.status(200).send('OK');
});

/*
  === PDF Overwrite Helper ===
  - Downloads signed file from Adobe, pushes to OTCS
  - Retries on 403 (Adobe race condition)
*/
const { pipeline } = require('stream');
const { promisify } = require('util');
const streamPipeline = promisify(pipeline);

async function overwritePdf(agreementId, tries = 0) {
  const info = MAP[agreementId];
  if (!info) return;

  const token = await ensureToken();
  const { nodeId, attachId, fileName } = info;
  const name = fileName?.trim() || `node_${nodeId}.pdf`;
  const filePath = path.join(INP_ROOT, name);

  try {
    const rsp = await axios.get(
      `${API_BASE}/api/rest/v6/agreements/${agreementId}/combinedDocument?attachAuditReport=true`,
      {
        responseType: 'stream',
        headers: { Authorization: `Bearer ${token}` },
        maxContentLength: 20 * 1024 * 1024 // 20 MB
      }
    );

    await streamPipeline(rsp.data, fs.createWriteStream(filePath));
    logger.info(`PDF Overwritten: ${filePath}`);

    const fileBuffer = fs.readFileSync(filePath); // Could refactor for stream support if needed
    await uploadToFolder(attachId, fileBuffer, name);
    logger.info(`Sent to folder ${attachId} on Content Server`);
  } catch (e) {
    if (e.response?.status === 403 && tries < 50) {
      setTimeout(() => overwritePdf(agreementId, tries + 1), 3000);
    } else {
      logger.error(`Upload failed: ${e.message}`);
    }
  }
}

/*
  === Keepalive / Self-ping (production only) ===
  - Prevents Render/hosting from idling the service
*/
if (process.env.NODE_ENV === 'production') {
  setInterval(() => {
    axios.get(`${NGROK_HOST}/health`)
      .then(() => console.log('[KEEPALIVE] Internal ping OK'))
      .catch(err => console.log(`[KEEPALIVE] Internal ping failed: ${err.message}`));
  }, 1000 * 60 * 10);
}

/*
  === Basic Auth for /auth and /logs endpoints ===
*/
function basicAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Logs"');
    return res.status(401).send('Authentication required.');
  }
  const [user, pass] = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
  if (
    user !== process.env.LOG_USER ||
    pass !== process.env.LOG_PASS
  ) {
    res.set('WWW-Authenticate', 'Basic realm="Logs"');
    return res.status(401).send('Invalid credentials.');
  }
  next();
}

/*
  === Audit Log Download Endpoint ===
  - Allows admin users to fetch/download the log file via HTTP basic auth
*/
app.get('/logs', basicAuth, (req, res) => {
  const logFilePath = process.env.NODE_ENV === 'production'
    ? '/tmp/audit.log'
    : path.join(__dirname, '../logs/audit.log');
  if (!fs.existsSync(logFilePath)) {
    return res.status(404).send('Log file not found.');
  }
  res.download(logFilePath, 'server.log');
});

// Fallback handler for unknown endpoints
app.use((_, res) => res.status(404).json({ error: 'Endpoint not found' }));

/*
  === Server Startup ===
*/
app.listen(PORT, () => {
  logger.info(
    `Server started successfully\n` +
    `  → Local:  http://localhost:${PORT}\n` +
    `  → Ngrok:  ${NGROK_HOST}\n\n`
  );
});
