const fs = require('fs');
const path = require('path');
const axios = require('axios');
require('dotenv').config();
const logger = require('../serverModules/logger');

const API_BASE = 'https://api.eu1.adobesign.com';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// Salva em /tmp/tokens.json no Render/produção, localmente como antes
const TOKENS_FILE = process.env.NODE_ENV === 'production'
  ? '/tmp/tokens.json'
  : path.resolve(__dirname, '../../tokens.json');
//console.log('[DEBUG] Token file path:', TOKENS_FILE);

let tok = { access_token: '', refresh_token: '', expires_at: 0 };

function load() {
  if (fs.existsSync(TOKENS_FILE)) {
    try {
      const content = fs.readFileSync(TOKENS_FILE, 'utf8');
      tok = JSON.parse(content);
      //  console.log('[DEBUG] TOKEN LOADED:', tok);
    } catch (err) {
      logger.error('Failed to read tokens.json:', err.message);
    }
  } else {
    logger.warn('tokens.json NOT FOUND');
  }
}

function save() {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tok, null, 2));
  //console.log('[DEBUG] TOKEN SAVED');
}

function setToken(acTok, expSec, refTok) {
  tok.access_token = acTok;
  tok.expires_at = Date.now() + expSec * 1000;
  if (refTok) tok.refresh_token = refTok;
  save();
}

async function ensureToken() {
  const now = Date.now();
  // console.log('[DEBUG] Checking token expiration:', tok.expires_at, now);

  if (tok.access_token && now < tok.expires_at - 30000) {
    // console.log('[DEBUG] Using existing access token');
    return tok.access_token;
  }

  if (!tok.refresh_token) {
    logger.error('Missing refresh token');
    throw new Error('REFRESH_TOKEN_MISSING');
  }

  try {
    // console.log('[DEBUG] Attempting token refresh...');
    const rsp = await axios.post(`${API_BASE}/oauth/v2/refresh`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: tok.refresh_token
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    setToken(rsp.data.access_token, rsp.data.expires_in, rsp.data.refresh_token);
    // console.log('[DEBUG] Token refreshed');
    return tok.access_token;
  } catch (err) {
    logger.error('Refresh failed:', err.response?.data || err.message);
    throw err;
  }
}

load();
module.exports = { setToken, ensureToken };
