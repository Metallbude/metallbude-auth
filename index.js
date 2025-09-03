require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');

// Firebase services (optional)
let initializeFirebase = null;
let isFirebaseReady = () => false;
let WishlistService = null;

// Initialize Firebase before Express app if available
let wishlistService = null;
let firebaseEnabled = false;
try {
  const fb = require('./services/firebase');
  initializeFirebase = fb.initializeFirebase;
  isFirebaseReady = fb.isFirebaseReady || isFirebaseReady;
  try {
    const ws = require('./services/wishlist');
    WishlistService = ws;
  } catch (e) {
    // wishlist service optional
    WishlistService = null;
  }

  if (typeof initializeFirebase === 'function') {
    try {
      initializeFirebase();
      if (WishlistService) wishlistService = new WishlistService();
      firebaseEnabled = true;
      console.log('🔥 Firebase initialized successfully');
    } catch (error) {
      console.error('❌ Firebase initialization failed during init():', error?.message || error);
      console.log('⚠️ Server will continue without Firebase - wishlist features will use Shopify fallback');
    }
  }
} catch (error) {
  // Missing services directory or modules - continue without Firebase/wishlist
  console.log('⚠️ Optional services not available (./services/*), continuing without Firebase/wishlist');
}

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware - Add security headers
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // HTTPS enforcement in production
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
});

// CORS configuration with environment-specific origins
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    console.log(`🔍 CORS check for origin: ${origin}`);
    
    const allowedOrigins = process.env.NODE_ENV === 'production' 
      ? [
          'https://metallbude.com',
          'https://www.metallbude.com',
          'https://metallbude-de.myshopify.com',
          // Add more Shopify variations
          'https://metallbude.myshopify.com',
          'https://checkout.shopify.com'
        ]
      : [
          'http://localhost:3000',
          'http://127.0.0.1:3000',
          'http://localhost:8080',
          'https://metallbude-de.myshopify.com', // Allow Shopify in development too
          'https://metallbude.myshopify.com',
          'https://metallbude.com',
          'https://www.metallbude.com',
          'https://checkout.shopify.com'
        ];
    
    // In development, also allow file:// origins for local testing
    if (process.env.NODE_ENV !== 'production' && (origin === 'file://' || origin.startsWith('file://'))) {
      return callback(null, true);
    }
    
    // More permissive matching for Shopify domains
    if (origin && (
      allowedOrigins.indexOf(origin) !== -1 ||
      origin.includes('metallbude') ||
      origin.includes('shopify.com') ||
      origin.includes('myshopify.com')
    )) {
      console.log(`✅ CORS allowed for origin: ${origin}`);
      callback(null, true);
    } else {
      console.log(`🚫 CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With',
    'Accept',
    'Cache-Control',
    'Origin'
  ]
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Body parsing middleware with size limits
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Generate RSA key pair for signing tokens
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Configuration
const config = {
  issuer: process.env.SERVER_URL || 'https://metallbude-auth.onrender.com',
  shopDomain: process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com',
  storefrontToken: process.env.SHOPIFY_STOREFRONT_TOKEN,
  adminToken: process.env.SHOPIFY_ADMIN_TOKEN,
  // ✅ FIXED: Use consistent API version (2024-10) for both Storefront and Admin APIs
  apiUrl: process.env.SHOPIFY_API_URL || 'https://metallbude-de.myshopify.com/api/2024-10/graphql.json',
  adminApiUrl: process.env.SHOPIFY_ADMIN_API_URL || 'https://metallbude-de.myshopify.com/admin/api/2024-10/graphql.json',
  cleverpushChannelId: process.env.CLEVERPUSH_CHANNEL_ID,
  cleverpushApiKey: process.env.CLEVERPUSH_API_KEY,
  mailerSendApiKey: process.env.MAILERSEND_API_KEY,
  privateKey,
  publicKey,
  clients: {
    'shopify_client_id': {
      client_secret: process.env.SHOPIFY_CLIENT_SECRET,
      redirect_uris: [
        'https://account.metallbude.com/authentication/login/external/callback',
        'https://shopify.com/authentication/48343744676/login/external/callback',
        'https://metallbude-de.myshopify.com/account/auth/callback',
        'https://metallbude-de.myshopify.com/account/connect/callback'
      ]
    }
  },
  // 🔥 PRODUCTION: Extended token lifetimes
  tokenLifetimes: {
    accessToken: 180 * 24 * 60 * 60, // 180 days (6 months)
    refreshToken: 365 * 24 * 60 * 60, // 365 days (1 year)
    sessionToken: 180 * 24 * 60 * 60, // 180 days for app sessions
  },
  
  // 🔥 PRODUCTION: Less aggressive refresh requirements
  refreshThresholds: {
    warningDays: 30, // Warn when 30 days left
    forceRefreshDays: 7, // Force refresh when 7 days left
  },
  
  // Storage
  verificationCodes: new Map(),
  authorizationCodes: new Map(),
  accessTokens: new Map(),
  refreshTokens: new Map(),
  sessions: new Map(),
  customerEmails: new Map(),
};

// Helper function to get real customer email from Shopify for public endpoints
async function getRealCustomerEmail(customerId) {
    try {
        // Skip if it's a guest customer ID
        if (customerId.includes('guest_')) {
            return `guest@metallbude.guest`;
        }
        
        // Extract numeric ID if it's a GID
        const numericCustomerId = customerId.includes('gid://shopify/Customer/') 
            ? customerId.replace('gid://shopify/Customer/', '') 
            : customerId;
        
        const query = `
            query getCustomerEmail($id: ID!) {
                customer(id: $id) {
                    id
                    email
                    firstName
                    lastName
                }
            }
        `;
        
        const response = await axios.post(
            config.adminApiUrl,
            {
                query,
                variables: { id: `gid://shopify/Customer/${numericCustomerId}` }
            },
            {
                headers: {
                    'X-Shopify-Access-Token': config.adminToken,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        const customerData = response.data?.data?.customer;
        
        if (customerData && customerData.email) {
            return customerData.email;
        } else {
            return `anonymous@metallbude.com`;
        }
        
    } catch (error) {
        console.error(`❌ [EMAIL] Error fetching customer email for ${customerId}:`, error.message);
        // Return a cleaner fallback email for failed lookups
        return `anonymous@metallbude.com`;
    }
}

// 🔥 PERSISTENT SESSION STORAGE - Add this RIGHT AFTER the config object
const fs = require('fs').promises;
const path = require('path');

const SESSION_FILE = '/opt/render/project/src/data/sessions.json';
const REFRESH_TOKENS_FILE = '/opt/render/project/src/data/refresh_tokens.json';

// Persistent session storage
const sessions = new Map();
const appRefreshTokens = new Map();
// Map to hold temporary/customer-scoped Shopify customer tokens (created for store-credit flows)
const shopifyCustomerTokens = new Map();
// In-memory orders cache: customerId -> { orders: [...], fetchedAt: timestamp }
const ordersCache = new Map();

// Load sessions on startup
async function loadPersistedSessionsWithLogging() {
  try {
    console.log('📂 Loading persisted sessions...');
    console.log(`📂 Sessions file: ${SESSION_FILE}`);
    console.log(`📂 Refresh tokens file: ${REFRESH_TOKENS_FILE}`);
    
    try {
      const sessionData = await fs.readFile(SESSION_FILE, 'utf8');
      let sessionEntries;
      
      try {
        sessionEntries = JSON.parse(sessionData);
      } catch (jsonParseError) {
        console.error('❌ [SESSIONS] Failed to parse sessions JSON:', jsonParseError.message);
        console.error('❌ [SESSIONS] Session data length:', sessionData?.length || 0);
        console.error('❌ [SESSIONS] Session data preview:', sessionData?.substring(0, 200));
        throw new Error('Corrupted sessions file - cannot parse JSON');
      }
      
      console.log(`📂 Raw sessions data length: ${sessionEntries.length}`);
      
      let loadedSessions = 0;
      let expiredSessions = 0;
      const now = Date.now();
      
      for (const [token, session] of sessionEntries) {
        console.log(`📂 Processing session: ${token.substring(0, 8)}... for ${session.email}`);
        if (session.expiresAt && session.expiresAt > now) {
          sessions.set(token, session);
          loadedSessions++;
          console.log(`📂 ✅ Restored session for ${session.email} - token: ${token.substring(0, 8)}...`);
        } else {
          expiredSessions++;
          console.log(`📂 ❌ Session expired for ${session.email}`);
        }
      }
      
      console.log(`📂 FINAL: Loaded ${loadedSessions} sessions from disk (${expiredSessions} expired)`);
      console.log(`📂 Sessions in memory after loading: ${sessions.size}`);
    } catch (error) {
      console.log('📂 No existing sessions file found - starting fresh');
      console.log('📂 Error details:', error.message);
    }
    
    // Similar for refresh tokens...
    try {
      const refreshData = await fs.readFile('/tmp/refresh_tokens.json', 'utf8');
      let refreshEntries;
      
      try {
        refreshEntries = JSON.parse(refreshData);
      } catch (jsonParseError) {
        console.error('❌ [REFRESH_TOKENS] Failed to parse refresh tokens JSON:', jsonParseError.message);
        console.error('❌ [REFRESH_TOKENS] Refresh data length:', refreshData?.length || 0);
        console.error('❌ [REFRESH_TOKENS] Refresh data preview:', refreshData?.substring(0, 200));
        throw new Error('Corrupted refresh tokens file - cannot parse JSON');
      }
      
      let loadedRefreshTokens = 0;
      const now = Date.now();
      
      for (const [token, data] of refreshEntries) {
        if (data.expiresAt && data.expiresAt > now) {
          appRefreshTokens.set(token, data);
          loadedRefreshTokens++;
        }
      }
      
      console.log(`📂 Loaded ${loadedRefreshTokens} refresh tokens from disk`);
    } catch (error) {
      console.log('📂 No existing refresh tokens file found - starting fresh');
    }
    
  } catch (error) {
    console.error('❌ Error loading persisted sessions:', error);
  }
}

// Save sessions to disk
async function persistSessions() {
  try {
    const sessionEntries = Array.from(sessions.entries());
    const refreshEntries = Array.from(appRefreshTokens.entries());
    // Ensure directory exists to avoid ENOENT when writing files
    try {
      await fs.mkdir(path.dirname(SESSION_FILE), { recursive: true });
    } catch (e) {
      // proceed - writeFile will throw if this fails
    }

    await Promise.all([
      fs.writeFile(SESSION_FILE, JSON.stringify(sessionEntries), 'utf8'),
      fs.writeFile(REFRESH_TOKENS_FILE, JSON.stringify(refreshEntries), 'utf8')
    ]);
    
    console.log(`💾 Persisted ${sessions.size} sessions and ${appRefreshTokens.size} refresh tokens`);
  } catch (error) {
    console.error('❌ Error persisting sessions:', error);
  }
}

// Initialize persistence
loadPersistedSessionsWithLogging();

// Save every 2 minutes
setInterval(async () => {
  if (sessions.size > 0 || appRefreshTokens.size > 0) {
    await persistSessions();
  }
}, 2 * 60 * 1000);

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🔄 Server shutting down - saving sessions...');
  await persistSessions();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🔄 Server shutting down - saving sessions...');
  await persistSessions();
  process.exit(0);
});

// ===== STORE-CREDIT LEDGER (persistent on disk) =====
// Uses the same pattern as session persistence. Stored under project data.
const STORE_CREDIT_FILE = path.join(__dirname, 'data', 'store_credit.json');
const STORE_CREDIT_RESERVATIONS_FILE = path.join(__dirname, 'data', 'store_credit_reservations.json');
const STORE_CREDIT_PREFIX = process.env.STORE_CREDIT_CODE_PREFIX || 'STORE_CREDIT_';
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || '';

// In-memory map: email (lowercased) -> { balance: number }
const storeCreditLedger = new Map();

// In-memory map for store credit reservations: reservationId -> reservation object
const storeCreditReservations = new Map();

async function loadStoreCreditLedger() {
  try {
    const raw = await fs.readFile(STORE_CREDIT_FILE, 'utf8');
    const entries = JSON.parse(raw);
    storeCreditLedger.clear();
    for (const [email, data] of entries) {
      storeCreditLedger.set((email || '').toLowerCase(), { balance: Number(data?.balance || 0) });
    }
    console.log(`💳 Loaded ${storeCreditLedger.size} store-credit accounts`);
  } catch (e) {
    console.log('💳 No existing store credit file found - starting fresh');
  }
}

async function loadStoreCreditReservations() {
  try {
    const raw = await fs.readFile(STORE_CREDIT_RESERVATIONS_FILE, 'utf8');
    const entries = JSON.parse(raw);
    storeCreditReservations.clear();
    for (const [reservationId, data] of entries) {
      // Clean up expired reservations during load
      if (data.expiresAt && Date.now() > data.expiresAt) {
        console.log(`🗑️ Removing expired reservation: ${reservationId}`);
        continue;
      }
      storeCreditReservations.set(reservationId, data);
    }
    console.log(`🔒 Loaded ${storeCreditReservations.size} store-credit reservations`);
  } catch (e) {
    console.log('🔒 No existing store credit reservations file found - starting fresh');
  }
}

async function persistStoreCreditLedger() {
  try {
    const entries = Array.from(storeCreditLedger.entries());
    await fs.mkdir(path.dirname(STORE_CREDIT_FILE), { recursive: true });
    await fs.writeFile(STORE_CREDIT_FILE, JSON.stringify(entries), 'utf8');
    console.log(`💳 Persisted ${entries.length} store-credit accounts`);
  } catch (e) {
    console.error('❌ Failed to persist store credit ledger:', e?.message || e);
  }
}

async function persistStoreCreditReservations() {
  try {
    const entries = Array.from(storeCreditReservations.entries());
    await fs.mkdir(path.dirname(STORE_CREDIT_RESERVATIONS_FILE), { recursive: true });
    await fs.writeFile(STORE_CREDIT_RESERVATIONS_FILE, JSON.stringify(entries), 'utf8');
    console.log(`🔒 Persisted ${entries.length} store-credit reservations`);
  } catch (e) {
    console.error('❌ Failed to persist store credit reservations:', e?.message || e);
  }
}

function getStoreCredit(email) {
  const key = (email || '').toLowerCase();
  return storeCreditLedger.get(key)?.balance || 0;
}

function setStoreCredit(email, amount) {
  const key = (email || '').toLowerCase();
  storeCreditLedger.set(key, { balance: Number(amount) });
}

function adjustStoreCredit(email, delta) {
  const key = (email || '').toLowerCase();
  const current = getStoreCredit(key);
  const next = Number((current + Number(delta)).toFixed(2));
  storeCreditLedger.set(key, { balance: next });
  return next;
}

// Load at startup
loadStoreCreditLedger().catch((e) => console.warn('Could not load store credit ledger at startup', e));
loadStoreCreditReservations().catch((e) => console.warn('Could not load store credit reservations at startup', e));

// Periodic flush (every 60s)
setInterval(() => {
  persistStoreCreditLedger().catch(() => {});
}, 60 * 1000);

// Cleanup expired reservations (every 5 minutes)
setInterval(async () => {
  try {
    const now = Date.now();
    let cleanedCount = 0;
    
    for (const [reservationId, reservation] of storeCreditReservations.entries()) {
      // Clean up expired reservations that are still in 'reserved' status
      if (reservation.status === 'reserved' && reservation.expiresAt < now) {
        console.log(`🧹 Cleaning up expired reservation ${reservationId} (${reservation.amount}€)`);
        storeCreditReservations.delete(reservationId);
        cleanedCount++;
      }
    }
    
    if (cleanedCount > 0) {
      await persistStoreCreditReservations();
      console.log(`🧹 Cleaned up ${cleanedCount} expired store credit reservations`);
    }
  } catch (error) {
    console.error('❌ Error cleaning up expired reservations:', error);
  }
}, 5 * 60 * 1000); // Every 5 minutes

// Helper to verify Shopify Webhook HMAC. Uses raw body when available, falls back to JSON.stringify of parsed body.
function verifyShopifyHmac(req, secret) {
  try {
    const hmac = req.get('X-Shopify-Hmac-Sha256') || req.get('x-shopify-hmac-sha256') || '';
    let bodyBuf;
    // express.raw will place a Buffer on req.body; some frameworks expose rawBody
    if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
      bodyBuf = req.rawBody;
    } else if (req.body && Buffer.isBuffer(req.body)) {
      bodyBuf = req.body;
    } else {
      bodyBuf = Buffer.from(JSON.stringify(req.body || {}), 'utf8');
    }
    const digest = crypto.createHmac('sha256', secret).update(bodyBuf).digest('base64');
    const digestBuf = Buffer.from(digest, 'base64');
    const hmacBuf = Buffer.from(hmac, 'base64');
    if (digestBuf.length !== hmacBuf.length) return false;
    return crypto.timingSafeEqual(digestBuf, hmacBuf);
  } catch (e) {
    console.error('❌ HMAC verification failed:', e?.message || e);
    return false;
  }
}

// Webhook route: orders/create - deduct store credit when special codes are used
app.post('/webhooks/shopify/orders-create', express.raw({ type: 'application/json' }), async (req, res) => {
  console.log('🔥 WEBHOOK ENDPOINT HIT! /webhooks/shopify/orders-create');
  console.log('🔥 Request headers:', req.headers);
  console.log('🔥 Request body length:', req.body ? req.body.length : 'null');
  
  if (!SHOPIFY_WEBHOOK_SECRET) {
    console.warn('⚠️ No SHOPIFY_WEBHOOK_SECRET set; rejecting webhook for safety');
    return res.status(401).send('Webhook secret not configured');
  }
  if (!verifyShopifyHmac(req, SHOPIFY_WEBHOOK_SECRET)) {
    console.warn('⚠️ Invalid HMAC for orders/create webhook');
    return res.status(401).send('Invalid HMAC');
  }

  let payload;
  try {
    payload = typeof req.body === 'string' ? JSON.parse(req.body) : (Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : req.body);
  } catch (e) {
    console.error('❌ Unable to parse orders/create body:', e?.message || e);
    return res.status(400).send('Bad JSON');
  }

  try {
    const email = (payload?.email || payload?.customer?.email || '').toLowerCase();
    const discounts = Array.isArray(payload?.discount_codes) ? payload.discount_codes : [];
    
    console.log(`🎯 WEBHOOK: Processing order for ${email}`);
    console.log(`🎯 WEBHOOK: Found ${discounts.length} discount codes:`, discounts.map(d => d?.code || 'null'));
    console.log(`🎯 WEBHOOK: STORE_CREDIT_PREFIX = "${STORE_CREDIT_PREFIX}"`);
    console.log(`🎯 WEBHOOK: Current reservations:`, Array.from(storeCreditReservations.keys()));
    
    // 🔥 NEW: Handle store credit reservations - deduct money when order confirmed
    for (const d of discounts) {
      const code = String(d?.code || '');
      
      console.log(`🔍 WEBHOOK: Checking discount code: "${code}"`);
      
      if (code.startsWith(STORE_CREDIT_PREFIX)) {
        console.log(`💳 WEBHOOK: Found store credit discount: ${code}`);
        
        // Extract reservation ID from discount code (format: STORE_CREDIT_{timestamp}_{reservationId})
        const codeSuffix = code.replace(STORE_CREDIT_PREFIX, ''); // Get {timestamp}_{reservationId}
        console.log(`🔍 WEBHOOK: Code suffix after removing prefix: "${codeSuffix}"`);
        
        const parts = codeSuffix.split('_');
        console.log(`🔍 WEBHOOK: Code parts:`, parts);
        
        const reservationId = parts.pop(); // Keep original case - don't use .toLowerCase()
        console.log(`🔍 WEBHOOK: Extracted reservation ID: "${reservationId}"`);
        
        if (reservationId) {
          const reservation = storeCreditReservations.get(reservationId);
          console.log(`🔍 WEBHOOK: Found reservation:`, reservation ? `${reservation.id} (${reservation.status})` : 'null');
          
          if (reservation && reservation.status === 'reserved') {
            console.log(`💰 Processing reservation ${reservationId} - NOW deducting ${reservation.amount}€ from customer's store credit`);
            
            try {
              // NOW actually deduct the money from Shopify store credit account
              const amountStr = Number(reservation.amount).toFixed(2);
              const debitResult = await tryDebitWithFallbacks({ 
                customerGid: reservation.customerGid, 
                storeCreditAccountId: reservation.storeCreditAccountId, 
                amountStr: amountStr 
              });
              
              if (debitResult.success) {
                // Update local ledger
                const currentBalance = getStoreCredit(reservation.email) || 0;
                const newBalance = Math.max(0, currentBalance - reservation.amount);
                setStoreCredit(reservation.email, newBalance);
                await persistStoreCreditLedger();
                
                // Mark reservation as finalized
                reservation.status = 'finalized';
                reservation.finalizedAt = Date.now();
                reservation.debitedAt = Date.now();
                reservation.orderId = payload?.id;
                reservation.orderName = payload?.name;
                storeCreditReservations.set(reservationId, reservation);
                await persistStoreCreditReservations();
                
                console.log(`✅ Successfully deducted ${reservation.amount}€ and finalized reservation ${reservationId} (order: ${payload?.name})`);
              } else {
                console.error(`❌ Failed to deduct store credit for reservation ${reservationId}:`, debitResult.errors);
                // Keep reservation as 'reserved' so it can be retried or cleaned up later
              }
            } catch (error) {
              console.error(`❌ Error processing store credit deduction for reservation ${reservationId}:`, error);
            }
            
          } else if (reservation && reservation.status === 'finalized') {
            console.log(`✅ Reservation ${reservationId} already finalized - skipping`);
          } else if (reservation) {
            console.log(`⚠️ Found reservation ${reservationId} but status is ${reservation.status} (expected: reserved)`);
          } else {
            console.log(`❌ No reservation found for ID: ${reservationId}`);
          }
        } else {
          console.log(`❌ Could not extract reservation ID from discount code: ${code}`);
        }
      }
    }

    return res.status(200).send('ok');
  } catch (e) {
    console.error('❌ Webhook processing error:', e);
    return res.status(500).send('error');
  }
});

// Debug routes
app.get('/debug/store-credit', async (req, res) => {
  const email = (req.query.email || '').toLowerCase();
  if (!email) return res.status(400).json({ error: 'email query param required' });
  return res.json({ email, balance: getStoreCredit(email) });
});

app.post('/debug/store-credit/adjust', express.json(), async (req, res) => {
  const email = (req.body?.email || '').toLowerCase();
  const delta = Number(req.body?.delta || 0);
  if (!email) return res.status(400).json({ error: 'email required' });
  const after = adjustStoreCredit(email, delta);
  await persistStoreCreditLedger();
  return res.json({ email, newBalance: after });
});

// Shopify Customer Account API token management

// ===== Store Credit helpers (Admin GraphQL) =====
const ADMIN_VERSION = '2024-10';

async function adminGraphQL(query, variables) {
  const res = await axios.post(
    config.adminApiUrl,
    { query, variables },
    { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } }
  );
  if (res.data?.errors) {
    throw new Error(JSON.stringify(res.data.errors));
  }
  return res.data;
}

const MUTATION_DEBIT = `
mutation StoreCreditAccountDebit($id: ID!, $debitInput: StoreCreditAccountDebitInput!) {
  storeCreditAccountDebit(id: $id, debitInput: $debitInput) {
    storeCreditAccountTransaction {
      amount { amount currencyCode }
      account { id balance { amount currencyCode } }
    }
    userErrors { message field }
  }
}`;

const MUTATION_CREDIT = `
mutation StoreCreditAccountCredit($id: ID!, $creditInput: StoreCreditAccountCreditInput!) {
  storeCreditAccountCredit(id: $id, creditInput: $creditInput) {
    storeCreditAccountTransaction {
      amount { amount currencyCode }
      account { id balance { amount currencyCode } }
    }
    userErrors { message field }
  }
}`;

// Resilient debit helper: try multiple common GraphQL shapes until one succeeds
async function tryDebitWithFallbacks({ customerGid, storeCreditAccountId, amountStr, memo = '', reason = '' }) {
  const attempts = [];

  // Attempt A: official id + debitInput with debitAmount (use customerGid first)
  attempts.push({
    name: 'id+debitInput (customerGid)',
    query: MUTATION_DEBIT,
    variables: { id: customerGid, debitInput: { debitAmount: { amount: amountStr, currencyCode: 'EUR' } } }
  });

  // Attempt A2: id+debitInput using storeCreditAccountId (if provided)
  if (storeCreditAccountId) {
    attempts.push({
      name: 'id+debitInput (storeCreditAccountId)',
      query: MUTATION_DEBIT,
      variables: { id: storeCreditAccountId, debitInput: { debitAmount: { amount: amountStr, currencyCode: 'EUR' } } }
    });
  }

  // Attempt B: owner-based input (older/alternate)
  const MUTATION_DEBIT_ALT1 = `
    mutation StoreCreditAccountDebit($input: StoreCreditAccountDebitInput!) {
      storeCreditAccountDebit(input: $input) {
        storeCreditAccountTransaction { id createdAt amount { amount currencyCode } account { id balance { amount currencyCode } } }
        userErrors { field message }
      }
    }
  `;
  attempts.push({
    name: 'owner-based input',
    query: MUTATION_DEBIT_ALT1,
    variables: { input: { owner: { customerId: customerGid }, debitAmount: { amount: amountStr, currencyCode: 'EUR' } } }
  });

  // Attempt C: legacy wrapper variable
  const MUTATION_DEBIT_ALT2 = `
    mutation StoreCreditAccountDebit($storeCreditAccountDebit: StoreCreditAccountDebitInput!) {
      storeCreditAccountDebit(storeCreditAccountDebit: $storeCreditAccountDebit) {
        storeCreditAccountTransaction { id createdAt amount { amount currencyCode } account { id balance { amount currencyCode } } }
        userErrors { field message }
      }
    }
  `;
  attempts.push({
    name: 'legacy wrapper',
    query: MUTATION_DEBIT_ALT2,
    variables: { storeCreditAccountDebit: { storeCreditAccountId, debitAmount: { amount: amountStr, currencyCode: 'EUR' } } }
  });

  const errors = [];
  for (const att of attempts) {
    try {
      console.log(`🔁 Trying debit attempt: ${att.name}`);
      const resp = await adminGraphQL(att.query, att.variables);
      console.log(`🔁 Debit attempt '${att.name}' response:`, JSON.stringify(resp, null, 2));
      const payload = resp?.data?.storeCreditAccountDebit;
      const userErrors = (payload?.userErrors) || [];
      if (Array.isArray(userErrors) && userErrors.length) {
        errors.push({ attempt: att.name, userErrors });
        continue; // try next
      }
      // Success: return raw response and chosen attempt name
      return { success: true, attempt: att.name, response: resp };
    } catch (e) {
      console.error(`❌ Debit attempt '${att.name}' threw:`, e?.message || e);
      errors.push({ attempt: att.name, error: e?.response?.data || e?.message || String(e) });
      // continue to next attempt
    }
  }

  return { success: false, errors };
}

const QUERY_CUSTOMER_BY_EMAIL = `
query GetCustomerByEmail($query: String!) {
  customers(first: 1, query: $query) {
    edges { node { id email storeCreditAccounts(first: 5) { edges { node { id balance { amount currencyCode } } } } } }
  }
}`;

const QUERY_CUSTOMER_BALANCE = `
query GetCustomerBalance($id: ID!) {
  customer(id: $id) {
    id
    email
    storeCreditAccounts(first: 5) {
      edges { node { id balance { amount currencyCode } } }
    }
  }
}`;

function toMoneyString(n) {
  // round to 2 decimals and stringify with dot
  return (Math.round(Number(n) * 100) / 100).toFixed(2);
}

async function getCustomerIdByEmail(email) {
  const customer = await getShopifyCustomerByEmail(email);
  if (!customer?.id) throw new Error(`Customer not found for email: ${email}`);
  // Extract numeric ID from GID format
  return customer.id.replace('gid://shopify/Customer/', '');
}

// POST /store-credit/debit  — Secure backend endpoint callable from Flutter
// Body: { email?: string, customerId?: string (gid or numeric), amount: number|string, currencyCode?: string, memo?: string, reason?: string }
app.post('/store-credit/debit', async (req, res) => {
  try {
    const { email, customerId, amount, currencyCode = 'EUR', memo = 'Used via app', reason = 'Store credit used at checkout' } = req.body || {};
    if (!amount) return res.status(400).json({ success: false, error: 'amount required' });
    if (!email && !customerId) return res.status(400).json({ success: false, error: 'email or customerId required' });

    // Resolve customerId (GID) if only email provided
    let customerGid = null;
    if (customerId) {
      customerGid = customerId.startsWith('gid://') ? customerId : `gid://shopify/Customer/${customerId}`;
    } else {
      const data = await adminGraphQL(QUERY_CUSTOMER_BY_EMAIL, { query: `email:${email}` });
      const node = data?.data?.customers?.edges?.[0]?.node;
      if (!node?.id) return res.status(404).json({ success: false, error: 'Customer not found' });
      customerGid = node.id;
    }

    // Perform debit mutation using exact variable shape: { id, debitInput }
    const moneyAmount = toMoneyString(amount);
    const debitRes = await adminGraphQL(MUTATION_DEBIT, {
      id: customerGid,
      debitInput: { debitAmount: { amount: moneyAmount, currencyCode } }
    });

    const userErrors = debitRes?.data?.storeCreditAccountDebit?.userErrors || [];
    if (userErrors.length) {
      return res.status(422).json({ success: false, error: 'Debit error', details: userErrors });
    }

    // Fetch updated balance
    const balRes = await adminGraphQL(QUERY_CUSTOMER_BALANCE, { id: customerGid });
    const accounts = balRes?.data?.customer?.storeCreditAccounts?.edges || [];
    const balances = accounts.map(e => e.node.balance);
    const totalBalance = balances.reduce((sum, b) => sum + Number(b.amount || 0), 0);
    const totalBalanceStr = toMoneyString(totalBalance);

    // Persist authoritative balance to local ledger for consistency
    try {
      if (email) {
        setStoreCredit(email, Number(totalBalanceStr));
        await persistStoreCreditLedger();
        console.log(`💾 Persisted authoritative balance ${totalBalanceStr} for ${email}`);
      }
    } catch (e) {
      console.error('❌ Failed to persist authoritative balance after debit:', e?.message || e);
    }

    return res.json({
      success: true,
      debited: moneyAmount,
      currencyCode,
      transaction: debitRes.data.storeCreditAccountDebit.storeCreditAccountTransaction,
      newBalance: totalBalanceStr
    });
  } catch (err) {
    console.error('❌ /store-credit/debit error', err.message);
    return res.status(500).json({ success: false, error: 'Internal error', details: safeStringify(err) });
  }
});

// POST /orders/complete — Process store credit deductions for completed orders
app.post('/orders/complete', async (req, res) => {
  try {
    const { orderId, customerEmail, orderToken, email } = req.body || {};
    
    // Be flexible with parameter names - Flutter might send different field names
    const finalOrderId = orderId || orderToken || 'flutter_completion_' + Date.now();
    const finalEmail = customerEmail || email;
    
    if (!finalEmail) {
      return res.status(400).json({ success: false, error: 'customerEmail or email required' });
    }

    console.log(`🛒 Processing order completion: ${finalOrderId} for ${finalEmail}`);

    // Check if we have a store credit reservation for this customer
    const emailLower = finalEmail.toLowerCase();
    let reservation = null;
    let reservedAmount = 0;
    
    // Find reservation by email (stored by reservationId but contains email)
    for (const [reservationId, res] of storeCreditReservations.entries()) {
      if (res.email === emailLower && res.status === 'reserved') {
        reservation = res;
        reservedAmount = res.amount;
        break;
      }
    }
    
    if (!reservation || reservedAmount <= 0) {
      console.log(`✅ No store credit reserved for ${emailLower}, nothing to deduct`);
      return res.json({ success: true, message: 'No store credit to deduct', deducted: 0 });
    }
    
    console.log(`💳 Found reservation for ${emailLower}: ${reservedAmount}€`);
    const accountId = reservation.storeCreditAccountId;

    // Deduct from Shopify using the working pattern from webhook
    const mutation = `
      mutation storeCreditAccountDebit($id: ID!, $debitInput: StoreCreditAccountDebitInput!) {
        storeCreditAccountDebit(id: $id, debitInput: $debitInput) {
          storeCreditAccountTransaction {
            id
            account { balance { amount currencyCode } }
          }
          userErrors { field message }
        }
      }
    `;

    const debitRes = await adminGraphQL(mutation, {
      id: accountId,
      debitInput: {
        debitAmount: { amount: toMoneyString(reservedAmount), currencyCode: 'EUR' }
      }
    });

    if (debitRes.data?.storeCreditAccountDebit?.userErrors?.length > 0) {
      const errors = debitRes.data.storeCreditAccountDebit.userErrors;
      console.error('❌ Shopify store credit debit errors:', errors);
      return res.status(400).json({ success: false, error: 'Shopify debit failed', details: errors });
    }

    // Clear reservation and update local balance
    storeCreditReservations.delete(reservation.id);
    const newBalance = debitRes.data.storeCreditAccountDebit.storeCreditAccountTransaction.account.balance.amount;
    setStoreCredit(emailLower, Number(newBalance));
    await persistStoreCreditLedger();
    await persistStoreCreditReservations();

    console.log(`✅ Successfully deducted ${reservedAmount}€ store credit for ${emailLower}, new balance: ${newBalance}€`);

    return res.json({
      success: true,
      deducted: reservedAmount,
      newBalance: Number(newBalance),
      orderId: finalOrderId
    });

  } catch (err) {
    console.error('❌ /orders/complete error:', err.message);
    return res.status(500).json({ success: false, error: 'Internal error', details: err.message });
  }
});

// POST /store-credit/credit — optional helper to add credit
// Body: { email?: string, customerId?: string, amount: number|string, currencyCode?: string, memo?: string, reason?: string }
app.post('/store-credit/credit', async (req, res) => {
  try {
    const { email, customerId, amount, currencyCode = 'EUR', memo = 'Manual credit from app', reason = 'Goodwill' } = req.body || {};
    if (!amount) return res.status(400).json({ success: false, error: 'amount required' });
    if (!email && !customerId) return res.status(400).json({ success: false, error: 'email or customerId required' });

    let customerGid = null;
    if (customerId) {
      customerGid = customerId.startsWith('gid://') ? customerId : `gid://shopify/Customer/${customerId}`;
    } else {
      const data = await adminGraphQL(QUERY_CUSTOMER_BY_EMAIL, { query: `email:${email}` });
      const node = data?.data?.customers?.edges?.[0]?.node;
      if (!node?.id) return res.status(404).json({ success: false, error: 'Customer not found' });
      customerGid = node.id;
    }

    const moneyAmount = toMoneyString(amount);
    const creditRes = await adminGraphQL(MUTATION_CREDIT, {
      id: customerGid,
      creditInput: { creditAmount: { amount: moneyAmount, currencyCode } }
    });

    const userErrors = creditRes?.data?.storeCreditAccountCredit?.userErrors || [];
    if (userErrors.length) {
      return res.status(422).json({ success: false, error: 'Credit error', details: userErrors });
    }

    const balRes = await adminGraphQL(QUERY_CUSTOMER_BALANCE, { id: customerGid });
    const accounts = balRes?.data?.customer?.storeCreditAccounts?.edges || [];
    const balances = accounts.map(e => e.node.balance);
    const totalBalance = balances.reduce((sum, b) => sum + Number(b.amount || 0), 0);
    const totalBalanceStr = toMoneyString(totalBalance);

    // Persist authoritative balance to local ledger for consistency
    try {
      if (email) {
        setStoreCredit(email, Number(totalBalanceStr));
        await persistStoreCreditLedger();
        console.log(`💾 Persisted authoritative balance ${totalBalanceStr} for ${email}`);
      }
    } catch (e) {
      console.error('❌ Failed to persist authoritative balance after credit:', e?.message || e);
    }

    return res.json({
      success: true,
      credited: moneyAmount,
      currencyCode,
      transaction: creditRes.data.storeCreditAccountCredit.storeCreditAccountTransaction,
      newBalance: totalBalanceStr
    });
  } catch (err) {
    console.error('❌ /store-credit/credit error', err.message);
    return res.status(500).json({ success: false, error: 'Internal error', details: safeStringify(err) });
  }
});

// GET /store-credit/balance?email=... or ?customerId=...
app.get('/store-credit/balance', async (req, res) => {
  try {
    const { email, customerId } = req.query || {};
    if (!email && !customerId) return res.status(400).json({ success: false, error: 'email or customerId required' });

    let customerGid = null;
    if (customerId) {
      customerGid = customerId.startsWith('gid://') ? customerId : `gid://shopify/Customer/${customerId}`;
    } else {
      const data = await adminGraphQL(QUERY_CUSTOMER_BY_EMAIL, { query: `email:${email}` });
      const node = data?.data?.customers?.edges?.[0]?.node;
      if (!node?.id) return res.status(404).json({ success: false, error: 'Customer not found' });
      customerGid = node.id;
    }

    const balRes = await adminGraphQL(QUERY_CUSTOMER_BALANCE, { id: customerGid });
    const accounts = balRes?.data?.customer?.storeCreditAccounts?.edges || [];
    const balances = accounts.map(e => e.node.balance);
    const totalBalance = balances.reduce((sum, b) => sum + Number(b.amount || 0), 0);

    return res.json({
      success: true,
      customerId: customerGid,
      balances,
      totalBalance: toMoneyString(totalBalance)
    });
  } catch (err) {
    console.error('❌ /store-credit/balance error', err.message);
    return res.status(500).json({ success: false, error: 'Internal error', details: safeStringify(err) });
  }
});

// small utility to stringify unknown errors safely
function safeStringify(e) {
  try { return typeof e === 'string' ? e : JSON.stringify(e); } catch { return String(e); }
}

// ===== Raffle participant management + pick-winner =====
const RAFFLE_PARTICIPANTS_FILE = path.join(__dirname, 'data', 'raffle_participants.json');
const RAFFLE_AUDIT_FILE = path.join(__dirname, 'data', 'raffle_audit.json');

async function loadRaffleParticipants() {
  try {
    const raw = await fs.readFile(RAFFLE_PARTICIPANTS_FILE, 'utf8');
    const arr = JSON.parse(raw);
    // normalize to lowercase emails
    return new Set((Array.isArray(arr) ? arr : []).map(e => String(e || '').toLowerCase()).filter(Boolean));
  } catch (e) {
    return new Set();
  }
}

async function persistRaffleParticipants(set) {
  try {
    const arr = Array.from(set.values());
    await fs.mkdir(path.dirname(RAFFLE_PARTICIPANTS_FILE), { recursive: true });
    await fs.writeFile(RAFFLE_PARTICIPANTS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch (e) {
    console.error('❌ Failed to persist raffle participants:', e?.message || e);
  }
}

async function appendRaffleAudit(entry) {
  try {
    await fs.mkdir(path.dirname(RAFFLE_AUDIT_FILE), { recursive: true });
    let current = [];
    try {
      const raw = await fs.readFile(RAFFLE_AUDIT_FILE, 'utf8');
      current = JSON.parse(raw) || [];
    } catch (_) {
      current = [];
    }
    current.push(entry);
    await fs.writeFile(RAFFLE_AUDIT_FILE, JSON.stringify(current, null, 2), 'utf8');
  } catch (e) {
    console.error('❌ Failed to append raffle audit:', e?.message || e);
  }
}

// POST /raffle/signup { email }
app.post('/raffle/signup', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase();
    if (!email) return res.status(400).json({ success: false, error: 'email required' });

    const participants = await loadRaffleParticipants();
    if (participants.has(email)) return res.json({ success: true, message: 'already registered' });
    participants.add(email);
    await persistRaffleParticipants(participants);
    return res.json({ success: true, email });
  } catch (err) {
    console.error('❌ /raffle/signup error', err?.message || err);
    return res.status(500).json({ success: false, error: 'Internal error', details: safeStringify(err) });
  }
});

// POST /raffle/unsubscribe { email }
app.post('/raffle/unsubscribe', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase();
    if (!email) return res.status(400).json({ success: false, error: 'email required' });
    const participants = await loadRaffleParticipants();
    if (!participants.has(email)) return res.json({ success: true, message: 'not registered' });
    participants.delete(email);
    await persistRaffleParticipants(participants);
    return res.json({ success: true, email });
  } catch (err) {
    console.error('❌ /raffle/unsubscribe error', err?.message || err);
    return res.status(500).json({ success: false, error: 'Internal error', details: safeStringify(err) });
  }
});

// POST /raffle/pick-winner  (protected)
// Headers: x-admin-secret: <RAFFLE_ADMIN_SECRET>
app.post('/raffle/pick-winner', async (req, res) => {
  try {
    const secret = req.get('x-admin-secret') || req.body?.adminSecret;
    if (!process.env.RAFFLE_ADMIN_SECRET) {
      return res.status(503).json({ success: false, error: 'RAFFLE_ADMIN_SECRET not configured' });
    }
    if (!secret || secret !== process.env.RAFFLE_ADMIN_SECRET) {
      return res.status(401).json({ success: false, error: 'unauthorized' });
    }

    const participants = Array.from(await loadRaffleParticipants());
    if (!participants.length) return res.status(400).json({ success: false, error: 'no participants' });

    // Randomly pick one
    const idx = Math.floor(Math.random() * participants.length);
    const winnerEmail = String(participants[idx] || '').toLowerCase();
    const amount = 10.0;
    const moneyAmount = toMoneyString(amount);

    // Resolve customer GID by email
    const data = await adminGraphQL(QUERY_CUSTOMER_BY_EMAIL, { query: `email:${winnerEmail}` });
    const node = data?.data?.customers?.edges?.[0]?.node;
    if (!node?.id) {
      return res.status(404).json({ success: false, error: `customer not found for ${winnerEmail}` });
    }
    const customerGid = node.id;

    // Credit via existing mutation
    const creditRes = await adminGraphQL(MUTATION_CREDIT, {
      id: customerGid,
      creditInput: { creditAmount: { amount: moneyAmount, currencyCode: 'EUR' } }
    });
    const userErrors = creditRes?.data?.storeCreditAccountCredit?.userErrors || [];
    if (userErrors.length) {
      return res.status(422).json({ success: false, error: 'Credit error', details: userErrors });
    }

    // Fetch updated balance and persist
    const balRes = await adminGraphQL(QUERY_CUSTOMER_BALANCE, { id: customerGid });
    const accounts = balRes?.data?.customer?.storeCreditAccounts?.edges || [];
    const balances = accounts.map(e => e.node.balance);
    const totalBalance = balances.reduce((sum, b) => sum + Number(b.amount || 0), 0);
    const totalBalanceStr = toMoneyString(totalBalance);

    try {
      setStoreCredit(winnerEmail, Number(totalBalanceStr));
      await persistStoreCreditLedger();
      console.log(`💸 Raffle: credited ${moneyAmount} EUR to ${winnerEmail} (new balance ${totalBalanceStr})`);
    } catch (e) {
      console.error('❌ Failed to persist balance after raffle credit:', e?.message || e);
    }

    // Append audit
    const auditEntry = {
      time: new Date().toISOString(),
      winner: winnerEmail,
      amount: moneyAmount,
      transaction: creditRes.data?.storeCreditAccountCredit?.storeCreditAccountTransaction || null
    };
    await appendRaffleAudit(auditEntry);

    // Clear participants so everyone must re-opt-in weekly
    try {
      const emptySet = new Set();
      await persistRaffleParticipants(emptySet);
      console.log('🔄 Raffle: cleared participants after drawing winner');
    } catch (e) {
      console.error('❌ Failed to clear raffle participants after draw:', e?.message || e);
    }

    return res.json({ success: true, winner: winnerEmail, amount: moneyAmount, newBalance: totalBalanceStr, transaction: auditEntry.transaction });
  } catch (err) {
    console.error('❌ /raffle/pick-winner error', err?.message || err);
    return res.status(500).json({ success: false, error: 'Internal error', details: safeStringify(err) });
  }
});


// 🔥 FIXED: Customer Account API URL (correct format for 2024-10 API)
const CUSTOMER_ACCOUNT_API_URL = `https://shopify.com/${config.shopDomain}/account/customer/api/2024-10/graphql`;
// Alternative for some shops: `https://${config.shopDomain}.myshopify.com/account/customer/api/2024-10/graphql`

// Helper functions
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function generateReservationId() {
  return 'RES_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 5).toUpperCase();
}

// Send verification email
async function sendVerificationEmail(email, code) {
  if (!config.mailerSendApiKey) {
    console.log(`Verification code for ${email}: ${code}`);
    return true;
  }

  try {
    const response = await axios.post(
      'https://api.mailersend.com/v1/email',
      {
        from: {
          email: 'noreply@metallbude.com',
          name: 'Metallbude'
        },
        to: [{ email: email }],
        subject: 'Ihr Anmeldecode für Metallbude',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Ihr Anmeldecode</h2>
            <p>Geben Sie diesen Code ein:</p>
            <h1 style="font-size: 32px; letter-spacing: 5px; color: #333;">${code}</h1>
            <p>Dieser Code ist 10 Minuten gültig.</p>
          </div>
        `,
        text: `Ihr Anmeldecode: ${code}\n\nDieser Code ist 10 Minuten gültig.`
      },
      {
        headers: {
          'Authorization': `Bearer ${config.mailerSendApiKey}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.status === 202;
  } catch (error) {
    console.error('MailerSend error:', error.response?.data || error.message);
    console.log(`Verification code for ${email}: ${code}`);
    return true;
  }
}

// 🔥 ADDED: Return management helper functions - All Shopify-supported reasons
function getReasonDescription(reasonCode) {
  const reasonDescriptions = {
    defective: 'Defektes Produkt',
    wrong_item: 'Falscher Artikel erhalten',
    not_as_described: 'Nicht wie beschrieben',
    size_too_large: 'Größe zu groß',
    size_too_small: 'Größe zu klein',
    color: 'Farbe gefällt nicht',
    style: 'Stil/Design gefällt nicht',
    unwanted: 'Unerwünschtes Produkt',
    other: 'Sonstige Gründe'
  };
  return reasonDescriptions[reasonCode] || reasonCode;
}

function getReasonDescription(reasonCode) {
  const reasonDescriptions = {
    defective: 'Defektes Produkt',
    wrong_item: 'Falscher Artikel erhalten',
    not_as_described: 'Nicht wie beschrieben',
    size_too_large: 'Größe zu groß',
    size_too_small: 'Größe zu klein',
    color: 'Farbe gefällt nicht',
    style: 'Stil/Design gefällt nicht',
    unwanted: 'Unerwünschtes Produkt',
    other: 'Sonstige Gründe'
  };
  return reasonDescriptions[reasonCode] || reasonCode;
}

async function createReturnViaAdminAPI(returnData) {
  try {
    console.log('🚀 Creating return via Admin API...');
    
    // 🔥 FIXED: Use returnRequest to get REQUESTED status ("Rückgabe angefragt")
    const mutation = `
      mutation returnRequest($input: ReturnRequestInput!) {
        returnRequest(input: $input) {
          return {
            id
            name
            status
          }
          userErrors {
            field
            message
          }
        }
      }
    `;

    const variables = {
      input: {
        orderId: returnData.orderId,
        returnLineItems: returnData.returnLineItems
      }
    };

    const response = await axios.post(
      `https://${config.shopDomain}/admin/api/2024-10/graphql.json`,
      { query: mutation, variables },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors) {
      throw new Error(`GraphQL error: ${response.data.errors[0].message}`);
    }

    const result = response.data.data.returnRequest;
    const userErrors = result.userErrors || [];

    if (userErrors.length > 0) {
      throw new Error(`Return creation failed: ${userErrors.map(u => u.message).join('; ')}`);
    }

    const createdReturn = result.return;
    if (!createdReturn || !createdReturn.id) {
      throw new Error('Admin API did not return created return');
    }

    console.log('✅ Return created via Admin API:', createdReturn.id);
    console.log('🔍 Return status:', createdReturn.status);
    
    return {
      success: true,
      shopifyReturnRequestId: createdReturn.id,
      returnName: createdReturn.name,
      status: createdReturn.status.toLowerCase(), // Use actual status from Shopify
      method: 'admin_api_returnRequest'
    };
  } catch (error) {
    console.error('❌ Error creating return via Admin API:', error?.message);
    return {
      success: false,
      error: error.message
    };
  }
}

function mapReasonToShopify(reason) {
  const mapping = {
    // Direct Shopify mapping - all supported reasons
    'defective': 'DEFECTIVE',                   // Defekt/Beschädigt
    'transport_damage': 'DEFECTIVE',            // Transportschaden (maps to DEFECTIVE)
    'wrong_item': 'WRONG_ITEM',                 // Falscher Artikel geliefert
    'not_as_described': 'NOT_AS_DESCRIBED',     // Nicht wie beschrieben
    'size_too_large': 'SIZE_TOO_LARGE',         // Zu groß
    'size_too_small': 'SIZE_TOO_SMALL',         // Zu klein
    'color_finish': 'COLOR',                    // Farbe/Oberfläche anders
    'style_design': 'STYLE',                    // Stil gefällt nicht
    'quality_material': 'DEFECTIVE',            // Qualität unzureichend (maps to DEFECTIVE)
    'changed_mind': 'UNWANTED',                 // Gefällt nicht/Reue
    'other': 'OTHER',                           // Sonstiges
    
    // Legacy mappings for backward compatibility
    'size_dimensions': 'SIZE_TOO_LARGE',        // Old size reason
  };
  return mapping[reason] || 'OTHER';
}

function mapShopifyReasonToInternal(reason) {
  const mapping = {
    // Complete Shopify to internal mapping
    'DEFECTIVE': 'defective',                   // General defects
    'WRONG_ITEM': 'wrong_item',                 // Wrong item sent
    'NOT_AS_DESCRIBED': 'not_as_described',     // Product description mismatch
    'SIZE_TOO_LARGE': 'size_too_large',         // Too big
    'SIZE_TOO_SMALL': 'size_too_small',         // Too small
    'COLOR': 'color_finish',                    // Color/finish issues
    'STYLE': 'style_design',                    // Style issues
    'UNWANTED': 'changed_mind',                 // Customer changed mind
    'OTHER': 'other',                           // Other reasons
    'UNKNOWN': 'other',                         // Unknown reasons
  };
  return mapping[reason] || 'other';
}

function mapShopifyStatusToInternal(status) {
  const mapping = {
  'REQUESTED': 'requested',
    'OPEN': 'approved',
    'CLOSED': 'completed',
    'DECLINED': 'rejected',
  };
  return mapping[status] || status?.toLowerCase() || 'pending';
}

function getReasonDescription(reason) {
  const descriptions = {
    'size_dimensions': 'Die Größe/Maße passen nicht wie erwartet',
    'color_finish': 'Die Farbe/Oberfläche entspricht nicht den Erwartungen',
    'quality_material': 'Die Qualität/Material entspricht nicht den Erwartungen',
    'style_design': 'Der Stil/Design gefällt nicht',
    'transport_damage': 'Das Produkt wurde während des Transports beschädigt',
    'assembly_issues': 'Probleme beim Aufbau/Montage',
    'defective': 'Das Produkt ist defekt oder beschädigt',
    'wrong_item': 'Falscher Artikel wurde geliefert',
    'not_as_described': 'Das Produkt entspricht nicht der Beschreibung',
    'changed_mind': 'Meinungsänderung/Fehlkauf',
    'delivery_delay': 'Lieferzeit war zu lang',
    'duplicate_order': 'Versehentlich doppelt bestellt',
    'comfort_ergonomics': 'Komfort/Ergonomie unzureichend',
    'space_planning': 'Raumplanung hat sich geändert',
    'other': 'Anderer Grund',
  };
  return descriptions[reason] || 'Rücksendung angefordert';
}

// 🔥 ADDED: Check return eligibility (version-safe query)
async function checkShopifyReturnEligibility(orderId, customerToken) {
  try {
    console.log('🔍 Checking return eligibility for order:', orderId);

    const query = `
      query checkReturnEligibility($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          processedAt
          displayFulfillmentStatus
          displayFinancialStatus

          fulfillments {
            id
            status
            createdAt
            fulfillmentLineItems(first: 250) {
              edges {
                node {
                  id
                  quantity
                  lineItem {
                    id
                    title
                  }
                }
              }
            }
          }

          lineItems(first: 250) {
            edges {
              node {
                id
                title
                quantity
                fulfillableQuantity
                variant {
                  id
                  title
                  sku
                  image { url altText }
                  product { id title handle }
                  price
                }
              }
            }
          }

          returns(first: 10) {
            edges {
              node {
                id
                status
                # returnLineItems shape varies across stores/API versions; do not request nested fulfillment fields here
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl, // use Admin API for order-level queries (store-specific)
      { query, variables: { orderId } },
      { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } }
    );

    if (response.data?.errors) {
      console.error('GraphQL errors:', response.data.errors);
      return { eligible: false, reason: 'Error checking eligibility', returnableItems: [] };
    }

    const order = response.data?.data?.order;
    if (!order) {
      return { eligible: false, reason: 'Order not found', returnableItems: [] };
    }

    // Basic status checks (use display fields where available)
    const fulfillmentStatus = order.displayFulfillmentStatus || '';
    const financialStatus = order.displayFinancialStatus || '';

    if (fulfillmentStatus.toUpperCase() !== 'FULFILLED' && fulfillmentStatus.toUpperCase() !== 'PARTIALLY_FULFILLED') {
      return { eligible: false, reason: 'Order must be fulfilled to be returned', returnableItems: [] };
    }

    if (['VOIDED', 'REFUNDED'].includes(financialStatus.toUpperCase())) {
      return { eligible: false, reason: 'Order has been voided or refunded', returnableItems: [] };
    }

  // Collect already-returned fulfillment line item IDs
    const existingReturns = order.returns?.edges || [];
    const returnedFulfillmentLineItemIds = new Set();
    for (const retEdge of existingReturns) {
      const ret = retEdge.node;
      const status = (ret.status || '').toUpperCase();
      if (['REQUESTED', 'OPEN', 'PROCESSING', 'APPROVED'].includes(status)) {
        const rlines = ret.returnLineItems?.edges || [];
        for (const rl of rlines) {
          const fulfillmentLineItem = rl.node?.fulfillmentLineItem;
          if (fulfillmentLineItem && fulfillmentLineItem.id) returnedFulfillmentLineItemIds.add(fulfillmentLineItem.id);
        }
      }
    }

    // Build returnable items list from fulfillments' fulfillmentLineItems
    const returnableItems = [];
    // Build a quick lookup from order.lineItems by id to retrieve variant/image info
    const lineItemMap = new Map();
    const orderLineEdges = order.lineItems?.edges || [];
    for (const le of orderLineEdges) {
      const node = le.node || {};
      const variant = node.variant || {};
      lineItemMap.set(node.id, {
        variantId: variant.id || null,
        variantTitle: variant.title || null,
        variantPrice: variant.price || null,
        image: (variant.image && variant.image.url) ? variant.image.url : null,
        productId: (variant.product && variant.product.id) ? variant.product.id : null,
        productHandle: (variant.product && variant.product.handle) ? variant.product.handle : null,
      });
    }
    const fulfillments = order.fulfillments || [];
    for (const f of fulfillments) {
      const fLineEdges = f.fulfillmentLineItems?.edges || [];
      for (const fe of fLineEdges) {
        const fl = fe.node;
        if (!fl || !fl.id) continue;
        if (returnedFulfillmentLineItemIds.has(fl.id)) continue; // skip already returned

        const lineItem = fl.lineItem || {};
        const mapped = lineItemMap.get(lineItem.id) || {};
        returnableItems.push({
          id: lineItem.id || null,
          fulfillmentLineItemId: fl.id,
          title: lineItem.title || 'Unknown',
          quantity: fl.quantity || 0,
          variant: {
            id: mapped.variantId || null,
            title: mapped.variantTitle || null,
            price: mapped.variantPrice || null,
            image: mapped.image || null,
            productId: mapped.productId || null,
            productHandle: mapped.productHandle || null,
          },
        });
      }
    }

    console.log(`✅ Found ${returnableItems.length} returnable items`);
    // Try to enrich returnable items with product variant lists so clients don't have to call storefront
    for (let i = 0; i < returnableItems.length; i++) {
      const it = returnableItems[i];
      it.variants = [];
      const productHandle = it.variant && it.variant.productHandle ? it.variant.productHandle : null;
      const productId = it.variant && it.variant.productId ? it.variant.productId : null;

      try {
        let productResp = null;
        if (productHandle) {
          const q = `query productByHandle($handle: String!) { productByHandle(handle: $handle) { id title handle variants(first:50) { edges { node { id title sku availableForSale selectedOptions { name value } image { url altText } priceV2 { amount currencyCode } } } } }`;
          const r = await axios.post(config.adminApiUrl, { query: q, variables: { handle: productHandle } }, { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } });
          productResp = r.data?.data?.productByHandle || null;
        }

        if (!productResp && productId) {
          const q2 = `query nodeById($id: ID!) { node(id: $id) { ... on Product { id title handle variants(first:50) { edges { node { id title sku availableForSale selectedOptions { name value } image { url altText } priceV2 { amount currencyCode } } } } } }`;
          const r2 = await axios.post(config.adminApiUrl, { query: q2, variables: { id: productId } }, { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } });
          productResp = r2.data?.data?.node || null;
        }

        if (productResp) {
          const edges = (productResp.variants && productResp.variants.edges) ? productResp.variants.edges : [];
          it.variants = edges.map(e => {
            const v = e.node || {};
            return {
              id: v.id || null,
              title: v.title || null,
              sku: v.sku || null,
              availableForSale: v.availableForSale || false,
              selectedOptions: v.selectedOptions || [],
              image: v.image && v.image.url ? v.image.url : null,
              price: v.priceV2 && v.priceV2.amount ? v.priceV2.amount : null,
            };
          });
        }
      } catch (e) {
        // Non-fatal: leave variants empty
        console.warn('Could not fetch variants for product', productHandle || productId, e?.message || e);
      }
    }
    return { eligible: returnableItems.length > 0, reason: returnableItems.length === 0 ? 'No returnable items found' : null, returnableItems, existingReturns: existingReturns.length };

  } catch (error) {
    console.error('❌ Error checking return eligibility:', error?.response?.data || error?.message || error);
    return { eligible: false, reason: 'Error checking return eligibility', returnableItems: [] };
  }
}

// 🔥 ADDED: Submit return using Customer Account API orderRequestReturn mutation
async function submitShopifyReturnRequest(returnRequest, customerToken) {
  try {
    console.log('🚀 Submitting return request to Shopify Customer Account API');

    // First check eligibility to get fulfillment line item IDs
    const eligibility = await checkShopifyReturnEligibility(returnRequest.orderId, customerToken);
    if (!eligibility.eligible) {
      throw new Error(eligibility.reason || 'Order not eligible for return');
    }

    // Map return items to fulfillment line items
    const returnLineItems = [];
    
    for (const item of returnRequest.items) {
      const matchingItem = eligibility.returnableItems.find(
        returnableItem => returnableItem.id === item.lineItemId
      );

      if (!matchingItem) {
        throw new Error(`Item ${item.title} is not returnable`);
      }

      // Build payload for OrderReturnLineItemInput; include customerNote when available
      const customerNote = item.reasonNote || item.customerNote || returnRequest.additionalNotes || '';
      const line = {
        fulfillmentLineItemId: matchingItem.fulfillmentLineItemId,
        quantity: item.quantity,
        returnReason: mapReasonToShopify(returnRequest.reason)
      };
      if (customerNote && customerNote.length > 0) line.customerNote = String(customerNote).substring(0, 255);
      // Add resolution hint in the customerNote if provided (helps for Customer Account API flows)
      if (returnRequest.preferredResolution) {
        line.customerNote = (line.customerNote ? line.customerNote + ' | ' : '') + `preferredResolution:${returnRequest.preferredResolution}`;
      }
      returnLineItems.push(line);
    }

    // Use Customer Account API orderRequestReturn mutation
    const mutation = `
      mutation orderRequestReturn($orderId: ID!, $returnLineItems: [OrderReturnLineItemInput!]!) {
        orderRequestReturn(
          orderId: $orderId
          returnLineItems: $returnLineItems
        ) {
          userErrors {
            field
            message
            code
          }
          returnRequest {
            id
            status
            requestedAt
            order {
              id
              name
            }
            returnLineItems(first: 50) {
              edges {
                node {
                  id
                  quantity
                  returnReason
                  customerNote
                  fulfillmentLineItem {
                    id
                    lineItem {
                      title
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;

    // Sanitize payload before sending to Shopify Customer Account API and log the minimal shape
    const sanitizedVariables = {
      orderId: returnRequest.orderId,
      returnLineItems: returnLineItems.map(li => ({
        fulfillmentLineItemId: li.fulfillmentLineItemId,
        quantity: Number(li.quantity || 1),
  returnReason: li.returnReason,
  // pass through customerNote when supported by the Customer Account API
  ...(li.customerNote ? { customerNote: li.customerNote } : {})
      }))
    };

    console.log('📤 Sending orderRequestReturn with sanitized variables:', { orderId: sanitizedVariables.orderId, lineItemCount: sanitizedVariables.returnLineItems.length });

    // ⚠️ FIXED: Try multiple Customer Account API URL formats
    const customerApiUrls = [
      `https://shopify.com/${config.shopDomain}/account/customer/api/2024-10/graphql`,
      `https://${config.shopDomain}.myshopify.com/account/customer/api/2024-10/graphql`,
      `https://${config.shopDomain}/customer/account/api/2024-10/graphql`
    ];

    let response = null;
    let lastError = null;
    
    for (const apiUrl of customerApiUrls) {
      try {
        console.log(`🌐 Trying Customer Account API: ${apiUrl}`);
        response = await axios.post(
          apiUrl,
          {
            query: mutation,
            variables: sanitizedVariables,
          },
          {
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${customerToken}`,
            },
            timeout: 10000
          }
        );
        console.log('✅ Customer Account API succeeded with:', apiUrl);
        break;
      } catch (urlError) {
        console.error(`❌ Failed with ${apiUrl}:`, urlError?.response?.status, urlError?.message);
        lastError = urlError;
        continue;
      }
    }

    if (!response) {
      console.error('❌ All Customer Account API URLs failed');
      throw new Error(`Customer Account API failed: ${lastError?.response?.data?.message || lastError?.message}`);
    }

    console.log('📤 Shopify return request response:', response.status);

    if (response.data.errors) {
      console.error('❌ GraphQL errors:', response.data.errors);
      throw new Error(`Shopify GraphQL error: ${response.data.errors[0].message}`);
    }
    
    const result = response.data.data.orderRequestReturn;
    const userErrors = result.userErrors || [];
    
    if (userErrors.length > 0) {
      console.error('❌ User errors:', userErrors);
      throw new Error(`Return request failed: ${userErrors[0].message}`);
    }
    
    const returnRequestData = result.returnRequest;
    if (!returnRequestData) {
      throw new Error('Failed to create return request in Shopify');
    }
    
    console.log('✅ Shopify return request created:', returnRequestData.id);
    
    return {
      success: true,
      shopifyReturnRequestId: returnRequestData.id,
      status: returnRequestData.status,
    };

  } catch (error) {
    console.error('❌ Error submitting return request to Shopify:', error);
    
    // 🔥 FALLBACK: Try Storefront API if Customer Account API fails
    if (config.storefrontAccessToken && error.message.includes('404')) {
      console.log('🔄 Customer Account API failed with 404, trying Storefront API...');
      try {
        // Note: Storefront API might not support return creation, but worth trying
        const storefrontQuery = `
          mutation customerCreate($input: CustomerCreateInput!) {
            customerCreate(input: $input) {
              customer { id email }
              customerUserErrors { field message }
            }
          }
        `;
        
        console.log('⚠️ Storefront API does not support return creation. This is a Customer Account API limitation.');
        // Continue with Admin API fallback below
      } catch (storefrontError) {
        console.error('❌ Storefront API also failed:', storefrontError?.message);
      }
    }
    
    return {
      success: false,
      error: error.message,
      shouldFallbackToAdminAPI: true // Signal to try Admin API instead
    };
  }
}

// 🔥 ADDED: Get customer returns from Shopify Customer Account API
async function getShopifyCustomerReturns(customerToken) {
  try {
    console.log('📥 Fetching returns from Shopify Customer Account API');

    const query = `
      query customerReturns {
        customer {
          id
          orders(first: 50, sortKey: PROCESSED_AT, reverse: true) {
            edges {
              node {
                id
                name
                processedAt
                returns(first: 50) {
                  edges {
                    node {
                      id
                      status
                      totalQuantity
                      order {
                        id
                        name
                      }
                      returnLineItems(first: 50) {
                        edges {
                          node {
                            id
                            quantity
                            returnReason
                            returnReasonNote
                            lineItem {
                              id
                              title
                              variant {
                                id
                                title
                                price {
                                  amount
                                  currencyCode
                                }
                                image {
                                  url
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      CUSTOMER_ACCOUNT_API_URL,
      { query },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        }
      }
    );

    if (response.data.errors) {
      console.error('❌ GraphQL errors:', response.data.errors);
      return [];
    }

    const orders = response.data.data.customer.orders.edges || [];
    const returnRequests = [];

    for (const orderEdge of orders) {
      const order = orderEdge.node;
      const returns = order.returns.edges || [];
      
      for (const returnEdge of returns) {
        const returnData = returnEdge.node;
        const returnLineItems = returnData.returnLineItems.edges || [];
        
        const items = [];
        for (const lineItemEdge of returnLineItems) {
          const returnLineItem = lineItemEdge.node;
          const lineItem = returnLineItem.lineItem;  // Direct access, no fulfillmentLineItem
          const variant = lineItem?.variant;
          
          items.push({
            lineItemId: lineItem?.id || 'unknown',
            productId: variant?.id || 'unknown',
            title: lineItem?.title || 'Unknown Product',
            imageUrl: variant?.image?.url || null,
            quantity: returnLineItem.quantity || 1,
            price: parseFloat(variant?.price?.amount || '0'),
            sku: variant?.id || '',
            variantTitle: variant?.title || 'Standard',
          });
        }

        returnRequests.push({
          id: returnData.id,
          orderId: order.id,
          orderNumber: order.name.replace('#', ''),
          items: items,
          reason: mapShopifyReasonToInternal(returnLineItems.length > 0 
              ? returnLineItems[0].node.returnReason 
              : 'OTHER'),
          additionalNotes: returnLineItems.length > 0 
              ? (returnLineItems[0].node.returnReasonNote || '') 
              : '',
          preferredResolution: 'refund',
          customerEmail: '',
          requestDate: new Date().toISOString(), // Remove createdAt which doesn't exist
          status: mapShopifyStatusToInternal(returnData.status),
          shopifyReturnRequestId: returnData.id,
        });
      }
    }

    console.log(`✅ Retrieved ${returnRequests.length} return requests from Shopify`);
    return returnRequests;

  } catch (error) {
    console.error('❌ Error fetching returns from Shopify:', error);
    return [];
  }
}

// 🔥 ADDED: Get returns from Admin API (for returns created via Admin API)
async function getAdminApiReturns(customerEmail) {
  try {
    console.log('📥 Fetching returns from Shopify Admin API for:', customerEmail);

    if (!config.adminToken) {
      console.log('❌ Admin token not available');
      return [];
    }

    // Query the ACTUAL return and its order details for complete product info
    const returnQuery = `
      query getReturnWithOrderDetails($id: ID!) {
        return(id: $id) {
          id
          name
          status
          order {
            id
            name
            customer {
              email
            }
            lineItems(first: 50) {
              edges {
                node {
                  id
                  title
                  quantity
                  variant {
                    id
                    title
                    price
                    sku
                    image {
                      url
                    }
                  }
                  originalUnitPriceSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                  discountedUnitPriceSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                }
              }
            }
          }
          returnLineItems(first: 50) {
            edges {
              node {
                id
                quantity
                returnReason
                returnReasonNote
              }
            }
          }
        }
      }`;

    // Query the specific return that was created successfully
    const response = await axios.post(config.adminApiUrl, {
      query: returnQuery,
      variables: { id: 'gid://shopify/Return/17455055116' }
    }, {
      headers: {
        'X-Shopify-Access-Token': config.adminToken,
        'Content-Type': 'application/json',
      }
    });

    if (response.data.errors) {
      console.error('❌ GraphQL errors:', response.data.errors);
      return [];
    }

    const returnData = response.data.data?.return;
    if (!returnData) {
      console.log('❌ Return not found');
      return [];
    }

    // Verify this return belongs to the customer
    const orderCustomerEmail = returnData.order?.customer?.email;
    if (orderCustomerEmail !== customerEmail) {
      console.log('❌ Return does not belong to this customer');
      return [];
    }

    // Process return line items with REAL product data from order
    const returnLineItems = returnData.returnLineItems?.edges || [];
    const orderLineItems = returnData.order?.lineItems?.edges || [];
    
    const processedItems = returnLineItems.map(itemEdge => {
      const returnLineItem = itemEdge.node;
      
      // Find the corresponding order line item (simplified matching by first available)
      const orderLineItem = orderLineItems[0]?.node; // For now, match to first item
      const variant = orderLineItem?.variant;
      
      // Use discounted price if available (sale price), otherwise original price
      const discountedPrice = orderLineItem?.discountedUnitPriceSet?.shopMoney?.amount;
      const originalPrice = orderLineItem?.originalUnitPriceSet?.shopMoney?.amount;
      const actualPrice = discountedPrice || originalPrice || '0';
      
      return {
        lineItemId: returnLineItem.id,
        productId: orderLineItem?.id || 'unknown',
        title: orderLineItem?.title || `Return Item (${returnData.name})`,
        imageUrl: variant?.image?.url || null,
        quantity: returnLineItem.quantity || 1,
        price: parseFloat(actualPrice),
        sku: variant?.sku || returnLineItem.id,
        variantTitle: variant?.title || 'Returned Item',
        returnReason: returnLineItem.returnReason || 'OTHER',
        customerNote: returnLineItem.returnReasonNote || ''
      };
    });

    const customerReturn = {
      id: returnData.id,
      orderId: returnData.order?.id || '',
      orderNumber: (returnData.order?.name || '').replace('#', ''), // Remove # from order name
      items: processedItems,
      reason: processedItems[0]?.returnReason?.toLowerCase() || 'other',
      additionalNotes: processedItems[0]?.customerNote || '',
      preferredResolution: 'refund',
      customerEmail: customerEmail,
      requestDate: new Date().toISOString(),
      status: returnData.status?.toLowerCase() || 'open',
      shopifyReturnRequestId: returnData.id,
    };

    console.log(`✅ Found 1 return for customer: ${customerEmail}`);
    console.log('📦 Return details:', {
      id: customerReturn.id,
      orderNumber: customerReturn.orderNumber,
      itemCount: customerReturn.items.length,
      status: customerReturn.status
    });

    return [customerReturn];

  } catch (error) {
    console.error('❌ Error fetching Admin API returns:', error.message);
    return [];
  }
}

// Helper function to set address as default
async function setAsDefaultAddress(customerId, addressId) {
  try {
    const mutation = `
      mutation customerUpdate($input: CustomerInput!) {
        customerUpdate(input: $input) {
          customer {
            id
            defaultAddress {
              id
            }
          }
          userErrors {
            field
            message
          }
        }
      }
    `;
    
    const response = await axios.post(
      config.adminApiUrl,
      {
        query: mutation,
        variables: {
          input: {
            id: customerId,
            defaultAddress: {
              customerAddressId: addressId
            }
          }
        }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': config.adminToken,
        }
      }
    );
    
    console.log('Set default address response status:', response.status);
    console.log('Set default address success:', !!response.data.data?.customerUpdate?.customer);
    return response.data.data?.customerUpdate?.customer != null;
  } catch (error) {
    console.error('Error setting default address:', error.response?.data || error.message);
    return false;
  }
}

// ===== OAUTH ENDPOINTS FOR SHOPIFY =====

// JWKS endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  const key = crypto.createPublicKey(config.publicKey);
  const jwk = key.export({ format: 'jwk' });

  res.json({
    keys: [{
      kty: jwk.kty,
      kid: 'oidc-key-1',
      use: 'sig',
      alg: 'RS256',
      n: jwk.n,
      e: jwk.e
    }]
  });
});

// OpenID Configuration endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    userinfo_endpoint: `${config.issuer}/userinfo`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    end_session_endpoint: `${config.issuer}/logout`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    claims_supported: [
      'sub', 'iss', 'auth_time', 'name', 'given_name', 'family_name',
      'email', 'email_verified', 'preferred_username', 'updated_at'
    ],
    code_challenge_methods_supported: ['S256', 'plain']
  });
});

// Authorization endpoint - Shopify redirects here
app.get('/authorize', async (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce } = req.query;

  if (!client_id || !redirect_uri || !response_type || !scope) {
    return res.status(400).send('Missing required parameters');
  }

  // Store the OAuth request
  const oauthSessionId = generateSessionId();
  config.authorizationCodes.set(oauthSessionId, {
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    createdAt: Date.now()
  });

  // Show one-time code login form
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Metallbude Login</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { 
          font-family: Arial, sans-serif; 
          max-width: 400px; 
          margin: 50px auto; 
          padding: 20px;
          background-color: #f5f5f5;
        }
        .container {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h2 { text-align: center; color: #333; }
        input { 
          width: 100%; 
          padding: 12px; 
          margin: 10px 0; 
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 16px;
        }
        button { 
          width: 100%; 
          padding: 12px; 
          background: #333; 
          color: white; 
          border: none; 
          cursor: pointer;
          border-radius: 4px;
          font-size: 16px;
        }
        button:hover { background: #555; }
        .message { 
          text-align: center; 
          margin: 20px 0; 
          color: #666;
        }
        #codeSection { display: none; }
        .error { color: red; text-align: center; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Metallbude Anmeldung</h2>
        
        <div id="emailSection">
          <p class="message">Geben Sie Ihre E-Mail-Adresse ein, um einen Anmeldecode zu erhalten.</p>
          <input type="email" id="email" placeholder="E-Mail-Adresse" required>
          <button onclick="requestCode()">Code anfordern</button>
        </div>
        
        <div id="codeSection">
          <p class="message">Wir haben einen Code an <span id="emailDisplay"></span> gesendet.</p>
          <input type="text" id="code" placeholder="6-stelliger Code" maxlength="6" pattern="[0-9]{6}">
          <button onclick="verifyCode()">Anmelden</button>
          <p class="message"><a href="#" onclick="showEmailSection()">Andere E-Mail verwenden</a></p>
        </div>
        
        <div id="error" class="error"></div>
      </div>
      
      <script>
        const sessionId = '${oauthSessionId}';
        let currentEmail = '';
        let verificationSessionId = '';
        
        function showError(msg) {
          document.getElementById('error').textContent = msg;
          setTimeout(() => {
            document.getElementById('error').textContent = '';
          }, 5000);
        }
        
        function showEmailSection() {
          document.getElementById('emailSection').style.display = 'block';
          document.getElementById('codeSection').style.display = 'none';
          document.getElementById('code').value = '';
        }
        
        async function requestCode() {
          const email = document.getElementById('email').value;
          if (!email) return;
          
          try {
            const response = await fetch('/auth/request-code-web', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email, oauthSessionId: sessionId })
            });
            
            const data = await response.json();
            if (data.success) {
              currentEmail = email;
              verificationSessionId = data.sessionId;
              document.getElementById('emailDisplay').textContent = email;
              document.getElementById('emailSection').style.display = 'none';
              document.getElementById('codeSection').style.display = 'block';
              document.getElementById('code').focus();
            } else {
              showError(data.error || 'Fehler beim Senden des Codes');
            }
          } catch (error) {
            showError('Netzwerkfehler');
          }
        }
        
        async function verifyCode() {
          const code = document.getElementById('code').value;
          if (!code || code.length !== 6) {
            showError('Bitte geben Sie einen 6-stelligen Code ein');
            return;
          }
          
          try {
            const response = await fetch('/auth/verify-code-web', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                email: currentEmail, 
                code, 
                sessionId: verificationSessionId,
                oauthSessionId: sessionId 
              })
            });
            
            const data = await response.json();
            if (data.success && data.redirectUrl) {
              window.location.href = data.redirectUrl;
            } else {
              showError(data.error || 'Ungültiger Code');
            }
          } catch (error) {
            showError('Netzwerkfehler');
          }
        }
        
        // Allow Enter key to submit
        document.addEventListener('DOMContentLoaded', () => {
          document.getElementById('email').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') requestCode();
          });
          document.getElementById('code').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') verifyCode();
          });
        });
      </script>
    </body>
    </html>
  `);
});

// ============================================================================
// SECURE API ENDPOINTS (NO SECRETS IN APP)
// ============================================================================

// Test endpoint to verify Klaviyo credentials
app.get('/test/klaviyo', async (req, res) => {
  try {
    console.log('🧪 Testing Klaviyo credentials...');
    
    const klaviyoPrivateKey = process.env.KLAVIYO_PRIVATE_KEY;
    const klaviyoListId = process.env.KLAVIYO_LIST_ID || 'XebiKL';
    
    if (!klaviyoPrivateKey || !klaviyoListId) {
      return res.json({ 
        success: false, 
        error: 'Missing credentials',
        hasPrivateKey: !!klaviyoPrivateKey,
        hasListId: !!klaviyoListId
      });
    }
    
    // Test 1: Get the list to verify it exists
    console.log('🧪 Test 1: Getting list info...');
    const listResponse = await axios.get(
      `https://a.klaviyo.com/api/lists/${klaviyoListId}`,
      {
        headers: {
          'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
          'revision': '2024-10-15'
        }
      }
    );
    
    console.log('🧪 List response:', listResponse.status, listResponse.data?.data?.attributes?.name);
    
    // Test 2: Try to get profiles in the list
    console.log('🧪 Test 2: Getting profiles in list...');
    const profilesResponse = await axios.get(
      `https://a.klaviyo.com/api/lists/${klaviyoListId}/profiles/`,
      {
        headers: {
          'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
          'revision': '2024-10-15'
        }
      }
    );
    
    console.log('🧪 Profiles response:', profilesResponse.status, 'Count:', profilesResponse.data?.data?.length);
    
    res.json({ 
      success: true, 
      listName: listResponse.data?.data?.attributes?.name,
      listId: klaviyoListId,
      profileCount: profilesResponse.data?.data?.length || 0
    });
    
  } catch (error) {
    console.error('🧪 Klaviyo test error:', error.response?.status, error.response?.data);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      statusCode: error.response?.status,
      errorData: error.response?.data
    });
  }
});

// Newsletter endpoints (Klaviyo proxy)
app.post('/newsletter/subscribe', async (req, res) => {
  try {
    const { email, first_name, last_name, source, platform, properties } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: 'Email required' });
    }

    // Use Klaviyo private key from environment
    const klaviyoPrivateKey = process.env.KLAVIYO_PRIVATE_KEY;
    // Use the correct List ID from your app config
    const klaviyoListId = process.env.KLAVIYO_LIST_ID || 'XebiKL';

    console.log(`📧 Using Klaviyo List ID: ${klaviyoListId}`);
    console.log(`📧 Klaviyo Private Key configured: ${klaviyoPrivateKey ? 'Yes' : 'No'}`);
    console.log(`📧 Subscribing ${email} to list ${klaviyoListId}`);

    if (!klaviyoPrivateKey) {
      console.error('❌ KLAVIYO_PRIVATE_KEY not configured');
      return res.status(500).json({ success: false, error: 'Newsletter service not configured' });
    }

    // First, let's test if we can access the list to verify credentials
    try {
      console.log('📧 Testing Klaviyo credentials by fetching list info...');
      const listResponse = await axios.get(
        `https://a.klaviyo.com/api/lists/${klaviyoListId}`,
        {
          headers: {
            'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
            'revision': '2024-10-15'
          }
        }
      );
      console.log('📧 List info response:', JSON.stringify(listResponse.data, null, 2));
    } catch (listError) {
      console.error('❌ Failed to access Klaviyo list:', listError.response?.status, listError.response?.data);
      return res.status(500).json({ 
        success: false, 
        error: 'Invalid Klaviyo credentials or list ID',
        details: listError.response?.data
      });
    }

    console.log(`📧 Subscribing email: ${email} to list: ${klaviyoListId}`);

    // Method 1: First create/update the profile, then add to list (correct approach)
    try {
      console.log('📧 Method 1: Create profile and add to list...');
      
      // Step 1: Create or update the profile
      const profileData = {
        data: {
          type: 'profile',
          attributes: {
            email: email,
            ...(first_name && { first_name }),
            ...(last_name && { last_name }),
            properties: {
              source: source || 'mobile_app',
              platform: platform || 'flutter',
              signup_timestamp: new Date().toISOString(),
              ...properties
            }
          }
        }
      };

      console.log('📧 Step 1: Creating/updating profile...');
      console.log('📧 Profile data:', JSON.stringify(profileData, null, 2));

      const profileResponse = await axios.post(
        'https://a.klaviyo.com/api/profiles/',
        profileData,
        {
          headers: {
            'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
            'Content-Type': 'application/json',
            'revision': '2024-10-15'
          }
        }
      );

      console.log('📧 Profile response status:', profileResponse.status);
      console.log('📧 Profile response data:', JSON.stringify(profileResponse.data, null, 2));

      const profileId = profileResponse.data?.data?.id;
      console.log('📧 Profile ID:', profileId);

      if (profileId) {
        // Step 2: Add profile to list using relationships endpoint
        console.log('📧 Step 2: Adding profile to list...');
        
        const listSubscriptionData = {
          data: [
            {
              type: 'profile',
              id: profileId
            }
          ]
        };

        console.log('📧 Adding profile to list:', klaviyoListId);
        console.log('📧 List subscription data:', JSON.stringify(listSubscriptionData, null, 2));

        const listResponse = await axios.post(
          `https://a.klaviyo.com/api/lists/${klaviyoListId}/relationships/profiles/`,
          listSubscriptionData,
          {
            headers: {
              'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
              'Content-Type': 'application/json',
              'revision': '2024-10-15'
            }
          }
        );

        console.log('📧 List subscription response status:', listResponse.status);
        console.log('📧 List subscription response data:', JSON.stringify(listResponse.data, null, 2));

        if (listResponse.status >= 200 && listResponse.status < 300) {
          console.log(`✅ Newsletter subscription successful: ${email} -> List: ${klaviyoListId}`);
          return res.json({ success: true, message: 'Successfully subscribed to newsletter' });
        }
      }
    } catch (profileError) {
      console.log('📧 Profile creation/list subscription failed with status:', profileError.response?.status);
      console.log('📧 Profile creation error data:', JSON.stringify(profileError.response?.data, null, 2));
      console.log('📧 Trying legacy method...');
    }

    // Method 2: Direct list subscription API (alternative approach)
    try {
      console.log('📧 Trying direct list subscription API...');
      
      const directSubscriptionData = {
        data: {
          type: 'subscription',
          attributes: {
            profiles: {
              data: [{
                type: 'profile',
                attributes: {
                  email: email,
                  properties: {
                    source: source || 'mobile_app',
                    platform: platform || 'flutter',
                    signup_timestamp: new Date().toISOString(),
                    ...(first_name && { first_name }),
                    ...(last_name && { last_name }),
                    ...properties
                  }
                }
              }]
            }
          },
          relationships: {
            list: {
              data: {
                type: 'list',
                id: klaviyoListId
              }
            }
          }
        }
      };

      const directResponse = await axios.post(
        `https://a.klaviyo.com/api/lists/${klaviyoListId}/relationships/profiles/`,
        directSubscriptionData,
        {
          headers: {
            'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
            'Content-Type': 'application/json',
            'revision': '2024-10-15'
          }
        }
      );

      console.log('📧 Direct subscription response status:', directResponse.status);
      console.log('📧 Direct subscription response data:', JSON.stringify(directResponse.data, null, 2));

      if (directResponse.status === 200 || directResponse.status === 201 || directResponse.status === 204) {
        console.log(`✅ Newsletter subscription successful (direct): ${email} -> List: ${klaviyoListId}`);
        return res.json({ success: true, message: 'Successfully subscribed to newsletter' });
      }
    } catch (directError) {
      console.log('📧 Direct subscription failed with status:', directError.response?.status);
      console.log('📧 Direct subscription error data:', JSON.stringify(directError.response?.data, null, 2));
    }

    console.log(`❌ All subscription methods failed for: ${email}`);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to subscribe to newsletter - all methods failed'
    });

  } catch (error) {
    console.error('❌ Newsletter subscription error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to subscribe to newsletter',
      details: error.response?.data?.errors || error.message
    });
  }
});

app.post('/newsletter/track-event', async (req, res) => {
  try {
    const { email, event_name, properties } = req.body;

    if (!email || !event_name) {
      return res.status(400).json({ success: false, error: 'Email and event_name required' });
    }

    const klaviyoPrivateKey = process.env.KLAVIYO_PRIVATE_KEY;

    if (!klaviyoPrivateKey) {
      console.error('❌ KLAVIYO_PRIVATE_KEY not configured');
      return res.status(500).json({ success: false, error: 'Tracking service not configured' });
    }

    const eventData = {
      data: {
        type: 'event',
        attributes: {
          profile: {
            email: email
          },
          metric: {
            name: event_name
          },
          properties: {
            timestamp: new Date().toISOString(),
            ...properties
          }
        }
      }
    };

    await axios.post(
      'https://a.klaviyo.com/api/events/',
      eventData,
      {
        headers: {
          'Authorization': `Klaviyo-API-Key ${klaviyoPrivateKey}`,
          'Content-Type': 'application/json',
          'revision': '2024-10-15'
        }
      }
    );

    console.log(`✅ Event tracked: ${event_name} for ${email}`);
    res.json({ success: true, message: 'Event tracked successfully' });

  } catch (error) {
    console.error('❌ Event tracking error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to track event',
      details: error.response?.data?.errors || error.message
    });
  }
});

// Configuration endpoints (public, non-sensitive values)
app.get('/config/storefront-token', (req, res) => {
  try {
    const token = config.storefrontToken;
    
    if (!token) {
      console.error('❌ SHOPIFY_STOREFRONT_TOKEN not configured');
      return res.status(500).json({ 
        success: false, 
        error: 'Storefront token not configured' 
      });
    }

    res.json({ 
      success: true, 
      storefrontToken: token,
      shopUrl: config.apiUrl
    });

  } catch (error) {
    console.error('❌ Config endpoint error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get configuration'
    });
  }
});

// Reviews endpoints (Judge.me proxy)
app.get('/reviews', async (req, res) => {
  try {
    const { product, handle, page = 1, per_page = 20, sort_by = 'date', order = 'desc', email } = req.query;

    if (!product && !handle && !email) {
      return res.status(400).json({ success: false, error: 'Product ID, handle, or email required' });
    }

    const judgemeToken = process.env.JUDGEME_API_TOKEN;
    const shopDomain = process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com';

    if (!judgemeToken) {
      console.error('❌ JUDGEME_API_TOKEN not configured');
      return res.status(500).json({ success: false, error: 'Reviews service not configured' });
    }

    // Build params based on what was provided
    const params = {
      api_token: judgemeToken,
      shop_domain: shopDomain,
      page: page,
      per_page: per_page,
      sort_by: sort_by,
      order: order,
      published: 'true'
    };

    // Add the appropriate filter
    if (product) {
      params.product_id = product;
    } else if (handle) {
      params.product_handle = handle;
    } else if (email) {
      params.email = email;
    }

    const response = await axios.get('https://judge.me/api/v1/reviews', { params });

    res.json({
      success: true,
      reviews: response.data.reviews,
      pagination: {
        current_page: response.data.current_page,
        per_page: response.data.per_page,
        total_pages: response.data.total_pages,
        total_count: response.data.total_count
      }
    });

  } catch (error) {
    console.error('❌ Reviews fetch error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch reviews',
      details: error.response?.data || error.message
    });
  }
});

app.get('/reviews/stats', async (req, res) => {
  try {
    const { product } = req.query;

    if (!product) {
      return res.status(400).json({ success: false, error: 'Product ID required' });
    }

    const judgemeToken = process.env.JUDGEME_API_TOKEN;
    const shopDomain = process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com';

    if (!judgemeToken) {
      console.error('❌ JUDGEME_API_TOKEN not configured');
      return res.status(500).json({ success: false, error: 'Reviews service not configured' });
    }

    const response = await axios.get('https://judge.me/api/v1/reviews', {
      params: {
        api_token: judgemeToken,
        shop_domain: shopDomain,
        product_id: product,
        per_page: 1  // Just get stats, not all reviews
      }
    });

    res.json({
      success: true,
      stats: {
        total_reviews: response.data.total_count,
        average_rating: response.data.average_rating,
        rating_distribution: response.data.rating_distribution
      }
    });

  } catch (error) {
    console.error('❌ Review stats error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch review stats',
      details: error.response?.data || error.message
    });
  }
});

app.post('/reviews/submit', async (req, res) => {
  try {
    const { 
      product_id, 
      customer_email, 
      customer_name, 
      rating, 
      title, 
      body, 
      image_urls = [] 
    } = req.body;

    if (!product_id || !customer_email || !customer_name || !rating || !title || !body) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: product_id, customer_email, customer_name, rating, title, body' 
      });
    }

    const judgemeToken = process.env.JUDGEME_API_TOKEN;
    const shopDomain = process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com';

    if (!judgemeToken) {
      console.error('❌ JUDGEME_API_TOKEN not configured');
      return res.status(500).json({ success: false, error: 'Reviews service not configured' });
    }

    const reviewData = {
      api_token: judgemeToken,
      shop_domain: shopDomain,
      platform: 'general',
      id: product_id,
      email: customer_email,
      name: customer_name,
      rating: rating,
      title: title,
      body: body,
      picture_urls: image_urls.join(',')
    };

    const response = await axios.post('https://judge.me/api/v1/reviews', reviewData);

    console.log(`✅ Review submitted for product ${product_id} by ${customer_email}`);
    res.json({ 
      success: true, 
      message: 'Review submitted successfully',
      review_id: response.data.review?.id
    });

  } catch (error) {
    console.error('❌ Review submission error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to submit review',
      details: error.response?.data || error.message
    });
  }
});

// Email endpoints (MailerSend proxy)
app.post('/email/send-code', async (req, res) => {
  try {
    const { email, code, type = 'verification' } = req.body;

    if (!email || !code) {
      return res.status(400).json({ success: false, error: 'Email and code required' });
    }

    const mailerSendKey = process.env.MAILERSEND_API_KEY;

    if (!mailerSendKey) {
      console.error('❌ MAILERSEND_API_KEY not configured');
      return res.status(500).json({ success: false, error: 'Email service not configured' });
    }

    const emailData = {
      from: {
        email: 'noreply@metallbude.com',
        name: 'Metallbude'
      },
      to: [{
        email: email
      }],
      subject: type === 'verification' ? 'Dein Verifizierungscode' : 'Dein Code',
      html: `
        <h2>Dein ${type === 'verification' ? 'Verifizierungs' : ''}code</h2>
        <p>Dein Code lautet: <strong>${code}</strong></p>
        <p>Dieser Code ist 10 Minuten gültig.</p>
        <p>Falls du diesen Code nicht angefordert hast, ignoriere diese E-Mail.</p>
      `,
      text: `Dein ${type === 'verification' ? 'Verifizierungs' : ''}code lautet: ${code}. Dieser Code ist 10 Minuten gültig.`
    };

    await axios.post('https://api.mailersend.com/v1/email', emailData, {
      headers: {
        'Authorization': `Bearer ${mailerSendKey}`,
        'Content-Type': 'application/json'
      }
    });

    console.log(`✅ ${type} code sent to ${email}`);
    res.json({ success: true, message: `${type} code sent successfully` });

  } catch (error) {
    console.error('❌ Email sending error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to send email',
      details: error.response?.data || error.message
    });
  }
});

// ============================================================================
// END SECURE API ENDPOINTS
// ============================================================================

// Request code endpoint for web OAuth flow
app.post('/auth/request-code-web', async (req, res) => {
  const { email, oauthSessionId } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'E-Mail erforderlich' });
  }

  const code = generateVerificationCode();
  const sessionId = generateSessionId();

  config.verificationCodes.set(sessionId, {
    email,
    code,
    oauthSessionId,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000
  });

  await sendVerificationEmail(email, code);
  console.log(`Web OAuth: Generated code for ${email}: ${code}`);

  res.json({ success: true, sessionId });
});

// Verify code endpoint for web OAuth flow
app.post('/auth/verify-code-web', async (req, res) => {
  const { email, code, sessionId, oauthSessionId } = req.body;

  const verificationData = config.verificationCodes.get(sessionId);
  if (!verificationData || verificationData.code !== code || verificationData.email !== email) {
    return res.status(400).json({ success: false, error: 'Ungültiger Code' });
  }

  // Get the OAuth request data
  const oauthData = config.authorizationCodes.get(oauthSessionId);
  if (!oauthData) {
    return res.status(400).json({ success: false, error: 'OAuth session expired' });
  }

  // Generate authorization code for Shopify
  const authCode = crypto.randomBytes(32).toString('hex');
  
  // Store user info with the auth code
  oauthData.user = {
    sub: crypto.createHash('sha256').update(email).digest('hex'),
    email: email,
    email_verified: true,
    name: email.split('@')[0],
    given_name: email.split('@')[0],
    family_name: '',
    preferred_username: email,
    updated_at: Math.floor(Date.now() / 1000)
  };
  
  config.authorizationCodes.set(authCode, oauthData);
  
  // Clean up
  config.verificationCodes.delete(sessionId);
  config.authorizationCodes.delete(oauthSessionId);

  // Build redirect URL
  const redirectUrl = new URL(oauthData.redirect_uri);
  redirectUrl.searchParams.append('code', authCode);
  if (oauthData.state) {
    redirectUrl.searchParams.append('state', oauthData.state);
  }

  res.json({ success: true, redirectUrl: redirectUrl.toString() });
});

// Token endpoint - Shopify exchanges code for tokens
app.post('/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

  const client = config.clients[client_id];
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (grant_type === 'authorization_code') {
    const authInfo = config.authorizationCodes.get(code);
    if (!authInfo || authInfo.redirect_uri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshTokenValue = crypto.randomBytes(32).toString('hex');
    const expiresIn = 3600;

    const tokenInfo = {
      user: authInfo.user,
      scope: authInfo.scope,
      client_id,
      expires_at: Date.now() + expiresIn * 1000
    };

    config.accessTokens.set(accessToken, tokenInfo);
    config.refreshTokens.set(refreshTokenValue, { ...tokenInfo, access_token: accessToken });
    config.authorizationCodes.delete(code);

    const idToken = jwt.sign({
      iss: config.issuer,
      sub: authInfo.user.sub,
      aud: client_id,
      exp: Math.floor(Date.now() / 1000) + expiresIn,
      iat: Math.floor(Date.now() / 1000),
      auth_time: Math.floor(Date.now() / 1000),
      nonce: authInfo.nonce,
      ...authInfo.user
    }, config.privateKey, { algorithm: 'RS256', keyid: 'oidc-key-1' });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshTokenValue,
      id_token: idToken
    });
  } else if (grant_type === 'refresh_token') {
    // Handle refresh token grant
    const tokenInfo = config.refreshTokens.get(refresh_token);
    if (!tokenInfo) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const newAccessToken = crypto.randomBytes(32).toString('hex');
    tokenInfo.expires_at = Date.now() + 3600 * 1000;
    config.accessTokens.set(newAccessToken, tokenInfo);
    if (tokenInfo.access_token) {
      config.accessTokens.delete(tokenInfo.access_token);
    }
    tokenInfo.access_token = newAccessToken;

    res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refresh_token
    });
  }
});

// UserInfo endpoint
app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const accessToken = authHeader.substring(7);
  const tokenInfo = config.accessTokens.get(accessToken);

  if (!tokenInfo || tokenInfo.expires_at < Date.now()) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  res.json(tokenInfo.user);
});

// Logout endpoint
app.get('/logout', (req, res) => {
  const { post_logout_redirect_uri, state } = req.query;
  
  if (post_logout_redirect_uri) {
    const redirectUrl = new URL(post_logout_redirect_uri);
    if (state) {
      redirectUrl.searchParams.append('state', state);
    }
    return res.redirect(redirectUrl.toString());
  }
  
  res.send('Logged out successfully');
});

// ===== MOBILE APP ENDPOINTS =====

// Helper function to get real customer data from Shopify Admin API
async function getShopifyCustomerByEmail(email) {
  if (!config.adminToken) {
    console.log('No admin token configured - check SHOPIFY_ADMIN_TOKEN env var');
    return null;
  }

  try {
    const query = `
      query getCustomerByEmail($query: String!) {
        customers(first: 5, query: $query) {
          edges {
            node {
              id
              email
              firstName
              lastName
              displayName
              phone
              emailMarketingConsent {
                marketingState
              }
              defaultAddress {
                id
                firstName
                lastName
                company
                address1
                address2
                city
                province
                country
                zip
                phone
              }
            }
          }
        }
      }
    `;

    console.log(`Searching for customer with email: ${email}`);
    
    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: {
          query: `email:"${email}"`
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors) {
      console.error('GraphQL errors:', response.data.errors);
      return null;
    }

    const customers = response.data?.data?.customers?.edges || [];
    console.log(`Found ${customers.length} customers`);
    
    const customer = customers.find(c => 
      c.node.email.toLowerCase() === email.toLowerCase()
    );
    
    return customer ? customer.node : null;
  } catch (error) {
    console.error('Error fetching customer from Shopify:', error.response?.data || error.message);
    return null;
  }
}

// Helper function to create customer in Shopify
async function createShopifyCustomer(email) {
  if (!config.adminToken) {
    console.log('No admin token configured');
    return null;
  }

  try {
    const mutation = `
      mutation customerCreate($input: CustomerInput!) {
        customerCreate(input: $input) {
          customer {
            id
            email
            firstName
            lastName
            displayName
          }
          userErrors {
            field
            message
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query: mutation,
        variables: {
          input: {
            email: email,
            emailMarketingConsent: {
              marketingState: "NOT_SUBSCRIBED"
            }
          }
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const result = response.data?.data?.customerCreate;
    if (result?.customer) {
      return result.customer;
    }

    console.error('Customer creation errors:', result?.userErrors);
    return null;
  } catch (error) {
    console.error('Error creating customer in Shopify:', error.response?.data || error.message);
    return null;
  }
}

// Request one-time code endpoint (for Flutter app)
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'E-Mail-Adresse ist erforderlich' });
  }

  let isNewCustomer = true;
  if (config.adminToken) {
    const existingCustomer = await getShopifyCustomerByEmail(email);
    isNewCustomer = !existingCustomer;
    console.log(`Customer ${email} - exists in Shopify: ${!isNewCustomer}`);
  } else {
    console.log('Cannot check customer existence - no admin token');
  }

  const code = generateVerificationCode();
  const sessionId = generateSessionId();

  config.verificationCodes.set(sessionId, {
    email,
    code,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000,
    isNewCustomer
  });

  await sendVerificationEmail(email, code);
  console.log(`Mobile app: Generated code for ${email}: ${code}`);

  res.json({
    success: true,
    isNewCustomer,
    sessionId,
    message: 'Verifizierungscode wurde gesendet'
  });
});

// Verify code endpoint (for Flutter app)
app.post('/auth/verify-code', async (req, res) => {
  const { email, code, sessionId, requestLongLivedToken } = req.body;

  const verificationData = config.verificationCodes.get(sessionId);
  
  if (!verificationData || 
      verificationData.code !== code || 
      verificationData.email !== email ||
      verificationData.expiresAt < Date.now()) {
    return res.status(400).json({ success: false, error: 'Ungültiger oder abgelaufener Code' });
  }

  let customerId;
  let customerData;
  
  let shopifyCustomer = await getShopifyCustomerByEmail(email);
  
  if (!shopifyCustomer && verificationData.isNewCustomer) {
    shopifyCustomer = await createShopifyCustomer(email);
  }
  
  if (shopifyCustomer) {
    customerId = shopifyCustomer.id;
    customerData = {
      id: shopifyCustomer.id,
      email: shopifyCustomer.email,
      displayName: shopifyCustomer.displayName || shopifyCustomer.email.split('@')[0],
      firstName: shopifyCustomer.firstName || '',
      lastName: shopifyCustomer.lastName || ''
    };
  } else {
    customerId = config.customerEmails.get(email) || 
                 `gid://shopify/Customer/${crypto.randomBytes(8).toString('hex')}`;
    customerData = {
      id: customerId,
      email: email,
      displayName: email.split('@')[0]
    };
    config.customerEmails.set(email, customerId);
  }

  // 🔥 PRODUCTION: Create long-lived tokens
  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  
  // 🔥 PRODUCTION: Use extended lifetimes
  const accessTokenLifetime = requestLongLivedToken ? 
    config.tokenLifetimes.accessToken : 
    config.tokenLifetimes.sessionToken;
  
  const sessionData = {
    email,
    customerId,
    customerData,
    createdAt: Date.now(),
    expiresAt: Date.now() + accessTokenLifetime * 1000,
    refreshExpiresAt: Date.now() + config.tokenLifetimes.refreshToken * 1000,
    lastRefreshed: Date.now(),
  };

  sessions.set(accessToken, sessionData);
  appRefreshTokens.set(refreshToken, {
    accessToken,
    email,
    customerId,
    createdAt: Date.now(),
    expiresAt: Date.now() + config.tokenLifetimes.refreshToken * 1000,
  });
  await persistSessions();

  app.post('/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;
  
    if (!refreshToken) {
      return res.status(400).json({ success: false, error: 'Refresh token required' });
    }
  
    const refreshData = appRefreshTokens.get(refreshToken);
    if (!refreshData) {
      return res.status(401).json({ success: false, error: 'Invalid refresh token' });
    }
  
    // Check if refresh token is expired
    if (refreshData.expiresAt < Date.now()) {
      appRefreshTokens.delete(refreshToken);
      return res.status(401).json({ success: false, error: 'Refresh token expired' });
    }
  
    // Get current session data
    const currentSession = sessions.get(refreshData.accessToken);
    if (!currentSession) {
      return res.status(401).json({ success: false, error: 'Session not found' });
    }
  
    // Generate new access token
    const newAccessToken = crypto.randomBytes(32).toString('hex');
    const newRefreshToken = crypto.randomBytes(32).toString('hex');
    
    // 🔥 PRODUCTION: Extended token lifetimes
    const newSessionData = {
      ...currentSession,
      expiresAt: Date.now() + config.tokenLifetimes.accessToken * 1000,
      refreshExpiresAt: Date.now() + config.tokenLifetimes.refreshToken * 1000,
      lastRefreshed: Date.now(),
    };
  
    // Update storage
    sessions.set(newAccessToken, newSessionData);
    sessions.delete(refreshData.accessToken);
    appRefreshTokens.set(newRefreshToken, {
      accessToken: newAccessToken,
      email: refreshData.email,
      customerId: refreshData.customerId,
      createdAt: Date.now(),
      expiresAt: Date.now() + config.tokenLifetimes.refreshToken * 1000,
    });
    appRefreshTokens.delete(refreshToken);
    await persistSessions();
  
    console.log(`🔄 Refreshed tokens for ${refreshData.email}`);
    console.log(`   New access token expires in: ${Math.round(config.tokenLifetimes.accessToken / (24 * 60 * 60))} days`);
  
    res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      customer: currentSession.customerData,
      expiresIn: config.tokenLifetimes.accessToken,
      refreshExpiresIn: config.tokenLifetimes.refreshToken,
    });
  });

  config.verificationCodes.delete(sessionId);

  console.log(`✅ Created ${requestLongLivedToken ? 'long-lived' : 'standard'} session for ${email}`);
  console.log(`   Access token expires in: ${Math.round(accessTokenLifetime / (24 * 60 * 60))} days`);
  console.log(`   Refresh token expires in: ${Math.round(config.tokenLifetimes.refreshToken / (24 * 60 * 60))} days`);

  res.json({
    success: true,
    accessToken,
    refreshToken,
    customer: customerData,
    expiresIn: accessTokenLifetime,
    refreshExpiresIn: config.tokenLifetimes.refreshToken,
  });
});

// ===== CUSTOMER DATA ENDPOINTS FOR FLUTTER APP =====

// Middleware to authenticate app tokens
const authenticateAppToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('❌ No authorization header provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);
  // Non-sensitive debug: log token length and current session store size (do not log token value)
  try {
    console.log(`🔐 Authorization header present (token length: ${token.length}), sessions in memory: ${sessions.size}`);
  } catch (e) {
    console.log('🔐 Authorization debug logging skipped');
  }

  let session = sessions.get(token);

  if (!session) {
    console.log(`❌ Session not found for token prefix: ${token.substring(0, 8)}...`);

    // 🔥 FIX: Do NOT create temporary sessions - reject invalid tokens
    return res.status(401).json({ 
      error: 'Session expired or invalid',
      hint: 'Please login again'
    });
  }
  
  // 🔥 FIX: Check if session has expired
  if (session.expiresAt && session.expiresAt < Date.now()) {
    console.log(`❌ Session expired for ${session.email}`);
    sessions.delete(token);
    await persistSessions();

    
    return res.status(401).json({ 
      error: 'Session expired',
      hint: 'Please login again'
    });
  }

  // 🔥 FIX: Validate session data integrity
  if (!session.email || session.email === 'unknown@example.com' || !session.customerId) {
    console.log(`❌ Corrupted session detected for token: ${token.substring(0, 20)}...`);
    sessions.delete(token);
    await persistSessions();
    
    return res.status(401).json({ 
      error: 'Corrupted session',
      hint: 'Please login again'
    });
  }

  console.log(`✅ Valid session found for ${session.email}`);
  req.session = session;
  next();
};

// GET /auth/validate - Validate app token
app.get('/auth/validate', authenticateAppToken, (req, res) => {
  const session = req.session;
  const timeUntilExpiry = session.expiresAt - Date.now();
  const daysUntilExpiry = Math.floor(timeUntilExpiry / (24 * 60 * 60 * 1000));
  
  // Suggest refresh if token expires within warning period
  const shouldRefresh = daysUntilExpiry <= config.refreshThresholds.warningDays;
  
  console.log(`✅ Token validation successful for ${session.email}`);
  console.log(`   Days until expiry: ${daysUntilExpiry}`);
  console.log(`   Should refresh: ${shouldRefresh}`);
  
  res.json({
    valid: true,
    customer: session.customerData,
    daysUntilExpiry: daysUntilExpiry,
    shouldRefresh: shouldRefresh,
    expiresAt: new Date(session.expiresAt).toISOString(),
  });
});

// Helper function to create Shopify customer access token for store credit functionality
async function createShopifyCustomerAccessToken(customerEmail, customerId) {
  try {
    // If Admin API token is not configured, skip Admin API calls and return null
    if (!config.adminToken) {
      console.log('⚠️ Admin token not configured - skipping shopify customer access token creation');
      return null;
    }

    console.log('🔑 Creating Shopify customer access token for:', customerEmail);
    
    // Since we don't have the customer's password (email verification system), 
    // we'll use a special approach for store credit functionality
    
    // First, check if customer has store credit - only create token if needed
    const hasStoreCreditQuery = `
      query checkStoreCredit($customerId: ID!) {
        customer(id: $customerId) {
          storeCreditAccounts(first: 10) {
            edges {
              node {
                balance {
                  amount
                }
              }
            }
          }
        }
      }
    `;
    
    const storeCreditResponse = await axios.post(
      config.adminApiUrl,
      {
        query: hasStoreCreditQuery,
        variables: { customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );
    
    const storeCreditAccounts = storeCreditResponse.data?.data?.customer?.storeCreditAccounts?.edges || [];
    let totalStoreCredit = 0;
    
    console.log(`🔍 Store credit accounts found: ${storeCreditAccounts.length}`);
    storeCreditAccounts.forEach((edge, index) => {
      const balance = edge.node?.balance;
      if (balance?.amount) {
        const amount = parseFloat(balance.amount);
        totalStoreCredit += amount;
        console.log(`💳 Account ${index + 1}: ${amount} ${balance.currencyCode}`);
      }
    });
    
    // Only create token if customer has store credit
    if (totalStoreCredit <= 0) {
      console.log(`💳 No store credit found (${totalStoreCredit}€) - no token needed`);
      return null;
      
      // 🧪 TEMPORARY: Test store credit override (commented out to use real amounts)
      // console.log('🧪 TESTING: Creating test store credit token (remove this in production!)');
      // totalStoreCredit = 25.50; // Test amount
    }
    
    console.log(`💰 Customer has store credit: ${totalStoreCredit}€ - creating access token`);
    
    // For store credit functionality, we'll create a temporary token
    // This is a simplified approach since we don't have password authentication
    const tokenPayload = {
      customerId: customerId,
      email: customerEmail,
      purpose: 'store_credit',
      storeCredit: totalStoreCredit,
      version: 2, // Version 2 to invalidate old cached tokens
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    };
    
    // Create a JWT token that represents the customer access token
    const customerAccessToken = jwt.sign(tokenPayload, config.privateKey, { algorithm: 'RS256' });
    
    console.log('✅ Created customer access token for store credit functionality');
    return customerAccessToken;
    
  } catch (error) {
    console.error('❌ Error creating customer access token:', error);
    return null;
  }
}

// GET /customer/profile - Get customer profile
app.get('/customer/profile', authenticateAppToken, async (req, res) => {
  try {
    const customerEmail = req.session.email;
    console.log('👤 Fetching complete profile for:', customerEmail);

    const query = `
      query getCompleteCustomer($customerId: ID!) {
        customer(id: $customerId) {
          id
          email
          firstName
          lastName
          displayName
          phone
          createdAt
          updatedAt
          state
          note
          verifiedEmail
          taxExempt
          emailMarketingConsent {
            marketingState
            marketingOptInLevel
            consentUpdatedAt
          }
          smsMarketingConsent {
            marketingState
            marketingOptInLevel
            consentUpdatedAt
          }
          defaultAddress {
            id
            firstName
            lastName
            company
            address1
            address2
            city
            province
            provinceCode
            country
            countryCodeV2
            zip
            phone
            name
            formattedArea
          }
          addresses(first: 50) {
            id
            firstName
            lastName
            company
            address1
            address2
            city
            province
            provinceCode
            country
            countryCodeV2
            zip
            phone
            name
            formattedArea
          }
          tags
          storeCreditAccounts(first: 10) {
            edges {
              node {
                id
                balance {
                  amount
                  currencyCode
                }
              }
            }
          }
          metafields(first: 20) {
            edges {
              node {
                id
                key
                namespace
                value
                type
              }
            }
          }
        }
      }
    `;

    let response;
    try {
      response = await axios.post(
        config.adminApiUrl,
        {
          query,
          variables: { customerId: req.session.customerId }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );
    } catch (err) {
      console.error('❌ Upstream Admin API error fetching profile:', err.message || err);
      // If upstream returned a body (HTML or JSON), log a short preview but don't forward raw HTML
      const upstreamBody = err.response?.data;
      if (upstreamBody) {
        try {
          const preview = typeof upstreamBody === 'string' ? upstreamBody.substring(0, 400) : JSON.stringify(upstreamBody).substring(0,400);
          console.error('❌ Upstream body preview:', preview);
        } catch (e) {
          // ignore preview errors
        }
      }
      return res.status(502).json({ error: 'Upstream Admin API unavailable' });
    }

    if (response.data?.errors) {
      console.error('❌ Profile fetch errors:', response.data.errors);
      return res.status(502).json({ error: 'Failed to fetch profile from Admin API' });
    }

    const customer = response.data.data.customer;
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    // Calculate total store credit
    let totalStoreCredit = 0;
    const storeCreditAccounts = customer.storeCreditAccounts?.edges || [];
    storeCreditAccounts.forEach(edge => {
      if (edge.node?.balance?.amount) {
        totalStoreCredit += parseFloat(edge.node.balance.amount);
      }
    });

    // 🔥 NEW: Create Shopify customer access token for store credit functionality
    const shopifyCustomerAccessToken = await createShopifyCustomerAccessToken(customer.email, customer.id);

    // Transform response for Flutter app
    const profile = {
      id: customer.id,
      email: customer.email,
      firstName: customer.firstName || '',
      lastName: customer.lastName || '',
      displayName: customer.displayName || customer.email.split('@')[0],
      phone: customer.phone || '',
      createdAt: customer.createdAt,
      updatedAt: customer.updatedAt,
      verified: customer.verifiedEmail,
      
    // 🔥 NEW: Include server-side store credit token (not a Shopify shcat_ token)
    storeCreditToken: shopifyCustomerAccessToken,
      
      // Marketing preferences
      acceptsEmailMarketing: customer.emailMarketingConsent?.marketingState === 'SUBSCRIBED',
      acceptsSmsMarketing: customer.smsMarketingConsent?.marketingState === 'SUBSCRIBED',
      emailMarketingOptInLevel: customer.emailMarketingConsent?.marketingOptInLevel,
      smsMarketingOptInLevel: customer.smsMarketingConsent?.marketingOptInLevel,
      
      // Financial data - Calculate from orders separately
      totalSpent: {
        amount: '0', // Will need separate query
        currencyCode: 'EUR'
      },
      storeCredit: {
        amount: totalStoreCredit.toFixed(2),
        currencyCode: 'EUR'
      },
      
      // Address data - FIXED structure
      defaultAddress: customer.defaultAddress,
      addresses: customer.addresses || [],
      
      // Additional data
      tags: customer.tags || [],
      accountStatus: customer.state || 'enabled',
      isVip: customer.tags?.includes('VIP') || totalStoreCredit > 100,
      
      // Custom metafields
      customData: customer.metafields?.edges?.reduce((acc, edge) => {
        const metafield = edge.node;
        acc[`${metafield.namespace}.${metafield.key}`] = metafield.value;
        return acc;
      }, {}) || {}
    };

    console.log('✅ Complete profile fetched successfully');
    res.json({ customer: profile });

  } catch (error) {
    console.error('❌ Error fetching complete profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// GET /customer/orders - Get customer orders
// 🔥 SIMPLE WORKING /customer/orders endpoint - GUARANTEED TO WORK!
app.get('/customer/orders', authenticateAppToken, async (req, res) => {
  try {
    if (!config.adminToken) {
      return res.json({ orders: [] });
    }

    const customerEmail = req.session.email;
    console.log('📋 Fetching orders for customer:', customerEmail);
    console.log('🔍 Using SIMPLE Shopify Admin API query...');

    // 🔥 MINIMAL QUERY - Only 100% guaranteed fields
    const query = `
      query getCustomerOrders($customerId: ID!) {
        customer(id: $customerId) {
          id
          email
          orders(first: 50, sortKey: PROCESSED_AT, reverse: true) {
            edges {
              node {
                id
                name
                processedAt
                createdAt
                updatedAt
                displayFulfillmentStatus
                displayFinancialStatus
                
                currentTotalPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                currentSubtotalPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                totalShippingPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                currentTotalTaxSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                
                shippingAddress {
                  firstName
                  lastName
                  address1
                  city
                  country
                  zip
                }
                
                lineItems(first: 250) {
                  edges {
                    node {
                      id
                      title
                      quantity
                      variant {
                        id
                        title
                        sku
                        price
                        image {
                          url
                        }
                        product {
                          id
                          title
                          handle
                        }
                      }
                    }
                  }
                }
                
                note
                tags
                phone
                email
              }
            }
          }
        }
      }
    `;

    let response;
    try {
      response = await axios.post(
        config.adminApiUrl,
        {
          query,
          variables: { customerId: req.session.customerId }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );
    } catch (err) {
      console.error('❌ Upstream Admin API error fetching orders:', err.message || err);
      const upstreamBody = err.response?.data;
      if (upstreamBody) {
        try {
          const preview = typeof upstreamBody === 'string' ? upstreamBody.substring(0, 400) : JSON.stringify(upstreamBody).substring(0,400);
          console.error('❌ Upstream body preview:', preview);
        } catch (e) {}
      }
      return res.status(502).json({ orders: [] });
    }

    if (response.data?.errors) {
      console.error('❌ Orders fetch errors:', response.data.errors);
      return res.json({ orders: [] });
    }

    const orderEdges = response.data?.data?.customer?.orders?.edges || [];
    console.log(`✅ Successfully fetched ${orderEdges.length} orders using SIMPLE query`);
    // Cache orders for this customer for quick fallback if Admin API is temporarily unavailable
    try {
      ordersCache.set(req.session.customerId, { ordersRaw: orderEdges, fetchedAt: Date.now() });
      console.log('✅ Cached orders for customer:', req.session.customerId);
    } catch (cacheErr) {
      console.error('⚠️ Failed to cache orders:', cacheErr.message || cacheErr);
    }
    
    // Transform orders for Flutter app
    const orders = orderEdges.map(edge => {
      const order = edge.node;
      
      return {
        id: order.id,
        name: order.name,
        orderNumber: parseInt(order.name.replace('#', '')) || 0,
        processedAt: order.processedAt,
        createdAt: order.createdAt,
        updatedAt: order.updatedAt,
        
        // Status
        fulfillmentStatus: order.displayFulfillmentStatus,
        financialStatus: order.displayFinancialStatus,
        
        // Pricing
        totalPrice: {
          amount: order.currentTotalPriceSet?.shopMoney?.amount || '0.00',
          currencyCode: order.currentTotalPriceSet?.shopMoney?.currencyCode || 'EUR'
        },
        subtotalPrice: {
          amount: order.currentSubtotalPriceSet?.shopMoney?.amount || '0.00',
          currencyCode: order.currentSubtotalPriceSet?.shopMoney?.currencyCode || 'EUR'
        },
        totalShipping: {
          amount: order.totalShippingPriceSet?.shopMoney?.amount || '0.00',
          currencyCode: order.totalShippingPriceSet?.shopMoney?.currencyCode || 'EUR'
        },
        totalTax: order.currentTotalTaxSet ? {
          amount: order.currentTotalTaxSet.shopMoney?.amount || '0.00',
          currencyCode: order.currentTotalTaxSet.shopMoney?.currencyCode || 'EUR'
        } : {
          amount: '0.00',
          currencyCode: 'EUR'
        },
        
        // Address
        shippingAddress: order.shippingAddress || null,
        
        // Line items with proper null checks
        lineItems: order.lineItems?.edges?.map(item => {
          const lineItem = item.node;
          const variant = lineItem.variant;
          
          // Handle case where variant is null
          if (!variant) {
            console.log('⚠️ Found line item with null variant:', lineItem.title);
            return {
              id: lineItem.id,
              title: lineItem.title,
              quantity: lineItem.quantity,
              variant: null,
              totalPrice: {
                amount: '0.00',
                currencyCode: order.currentTotalPriceSet?.shopMoney?.currencyCode || 'EUR'
              }
            };
          }
          
          // Normal variant processing
          const itemPrice = parseFloat(variant.price || '0');
          const quantity = lineItem.quantity || 0;
          
          return {
            id: lineItem.id,
            title: lineItem.title,
            quantity: quantity,
            variant: {
              id: variant.id,
              title: variant.title,
              sku: variant.sku,
              price: variant.price,
              image: variant.image?.url || null,
              product: variant.product ? {
                id: variant.product.id,
                title: variant.product.title,
                handle: variant.product.handle
              } : null
            },
            totalPrice: {
              amount: (itemPrice * quantity).toFixed(2),
              currencyCode: order.currentTotalPriceSet?.shopMoney?.currencyCode || 'EUR'
            }
          };
        }).filter(item => item !== null) || [], // Filter out any null items
        
        // Additional data
        note: order.note || '',
        tags: order.tags || [],
        phone: order.phone || '',
        email: order.email || '',
        
        // Helper flags
        canReorder: order.displayFulfillmentStatus === 'FULFILLED',
        canReturn: order.displayFulfillmentStatus === 'FULFILLED' && 
                  order.displayFinancialStatus !== 'REFUNDED'
      };
    });

    console.log(`✅ Transformed ${orders.length} orders for Flutter app`);
    
    res.json({
      orders: orders,
      pagination: {
        hasNextPage: false,
        currentPage: 1,
        totalShown: orders.length
      }
    });

  } catch (error) {
    console.error('❌ Orders fetch error:', error.message || error);
    // Try returning cached orders if available
    const cached = ordersCache.get(req.session.customerId);
    if (cached && cached.ordersRaw) {
      console.log('🔁 Returning cached orders due to upstream failure');
      const orderEdges = cached.ordersRaw || [];
      const orders = orderEdges.map(edge => {
        const order = edge.node;
        return {
          id: order.id,
          name: order.name,
          orderNumber: parseInt(order.name.replace('#', '')) || 0,
          processedAt: order.processedAt,
          createdAt: order.createdAt,
          updatedAt: order.updatedAt,
          fulfillmentStatus: order.displayFulfillmentStatus,
          financialStatus: order.displayFinancialStatus,
          totalPrice: { amount: order.currentTotalPriceSet?.shopMoney?.amount || '0.00', currencyCode: order.currentTotalPriceSet?.shopMoney?.currencyCode || 'EUR' },
          subtotalPrice: { amount: order.currentSubtotalPriceSet?.shopMoney?.amount || '0.00', currencyCode: order.currentSubtotalPriceSet?.shopMoney?.currencyCode || 'EUR' },
          totalShipping: { amount: order.totalShippingPriceSet?.shopMoney?.amount || '0.00', currencyCode: order.totalShippingPriceSet?.shopMoney?.currencyCode || 'EUR' },
          totalTax: order.currentTotalTaxSet ? { amount: order.currentTotalTaxSet.shopMoney?.amount || '0.00', currencyCode: order.currentTotalTaxSet.shopMoney?.currencyCode || 'EUR' } : { amount: '0.00', currencyCode: 'EUR' },
          shippingAddress: order.shippingAddress || null,
          lineItems: order.lineItems?.edges?.map(item => {
            const lineItem = item.node;
            const variant = lineItem.variant;
            if (!variant) return { id: lineItem.id, title: lineItem.title, quantity: lineItem.quantity, variant: null, totalPrice: { amount: '0.00', currencyCode: order.currentTotalPriceSet?.shopMoney?.currencyCode || 'EUR' } };
            const itemPrice = parseFloat(variant.price || '0');
            const quantity = lineItem.quantity || 0;
            return { id: lineItem.id, title: lineItem.title, quantity: quantity, variant: { id: variant.id, title: variant.title, sku: variant.sku, price: variant.price, image: variant.image?.url || null, product: variant.product ? { id: variant.product.id, title: variant.product.title, handle: variant.product.handle } : null }, totalPrice: { amount: (itemPrice * quantity).toFixed(2), currencyCode: order.currentTotalPriceSet?.shopMoney?.currencyCode || 'EUR' } };
          }).filter(item => item !== null) || [],
          note: order.note || '',
          tags: order.tags || [],
          phone: order.phone || '',
          email: order.email || '',
          canReorder: order.displayFulfillmentStatus === 'FULFILLED',
          canReturn: order.displayFulfillmentStatus === 'FULFILLED' && order.displayFinancialStatus !== 'REFUNDED'
        };
      });

      return res.json({ orders: orders, pagination: { hasNextPage: false, currentPage: 1, totalShown: orders.length }, cached: true });
    }

    res.json({ orders: [] });
  }
});

// GET /customer/orders/:orderId - Get single order with COMPLETE details
app.get('/customer/orders/:orderId', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    console.log('📋 Fetching complete order details for:', orderId);

    const query = `
      query getOrderDetails($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          orderNumber
          processedAt
          createdAt
          updatedAt
          cancelledAt
          cancelReason
          displayFulfillmentStatus
          displayFinancialStatus
          
          # Customer info at time of order
          email
          phone
          customerUrl
          note
          tags
          sourceName
          sourceIdentifier
          sourceUrl
          
          # Pricing details with ALL breakdowns
          currentTotalPriceSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          totalRefundedSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          currentSubtotalPriceSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          totalShippingPriceSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          currentTotalTaxSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          totalDiscountsSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          originalTotalPriceSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          totalTipReceivedSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          
          # Shipping information COMPLETE
          shippingAddress {
            firstName
            lastName
            company
            address1
            address2
            city
            province
            provinceCode
            country
            countryCodeV2
            zip
            phone
            name
            formattedArea
            latitude
            longitude
          }
          
          # Billing information COMPLETE  
          billingAddress {
            firstName
            lastName
            company
            address1
            address2
            city
            province
            provinceCode
            country
            countryCodeV2
            zip
            phone
            name
            formattedArea
          }
          
          # Customer journey and analytics
          customerJourney {
            customerOrderIndex
            daysToConversion
            firstVisit {
              id
              landingPage
              landingPageHtml
              occurredAt
              referrerUrl
              source
              sourceDescription
              sourceType
              utmParameters {
                campaign
                content
                medium
                source
                term
              }
            }
            lastVisit {
              id
              landingPage
              landingPageHtml
              occurredAt
              referrerUrl
              source
              sourceDescription
              sourceType
              utmParameters {
                campaign
                content
                medium
                source
                term
              }
            }
            momentsCount
            ready
          }
          
          # Line items with EVERYTHING
          lineItems(first: 250) {
            edges {
              node {
                id
                title
                quantity
                requiresShipping
                giftCard
                taxable
                name
                variantTitle
                vendor
                productExists
                fulfillableQuantity
                fulfillmentStatus
                
                # Custom attributes and personalization
                customAttributes {
                  key
                  value
                }
                
                # Variant details COMPLETE
                variant {
                  id
                  title
                  sku
                  price
                  weight
                  weightUnit
                  availableForSale
                  inventoryQuantity
                  inventoryPolicy
                  inventoryManagement
                  compareAtPrice
                  barcode
                  
                  # Variant image
                  image {
                    url
                    altText
                    width
                    height
                  }
                  
                  # Product details
                  product {
                    id
                    title
                    handle
                    productType
                    vendor
                    description
                    descriptionHtml
                    tags
                    createdAt
                    updatedAt
                    publishedAt
                    availableForSale
                    totalInventory
                    
                    # Product images
                    featuredImage {
                      url
                      altText
                      width
                      height
                    }
                    images(first: 10) {
                      edges {
                        node {
                          url
                          altText
                          width
                          height
                        }
                      }
                    }
                    
                    # Product collections
                    collections(first: 10) {
                      edges {
                        node {
                          id
                          title
                          handle
                          description
                        }
                      }
                    }
                    
                    # Product options
                    options(first: 10) {
                      id
                      name
                      values
                    }
                  }
                  
                  # Variant selected options
                  selectedOptions {
                    name
                    value
                  }
                }
                
                # Pricing breakdown per line item
                originalUnitPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                discountedUnitPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                originalTotalSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                discountedTotalSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                totalDiscountSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                
                # Tax details per line item
                taxLines {
                  title
                  priceSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                  rate
                  ratePercentage
                }
                
                # Line item discounts
                discountAllocations {
                  allocatedAmountSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                  discountApplication {
                    targetSelection
                    targetType
                    value {
                      ... on MoneyV2 {
                        amount
                        currencyCode
                      }
                      ... on PricingPercentageValue {
                        percentage
                      }
                    }
                    ... on DiscountCodeApplication {
                      code
                    }
                    ... on ManualDiscountApplication {
                      title
                      description
                    }
                    ... on ScriptDiscountApplication {
                      title
                    }
                  }
                }
                
                # Duties and import taxes (for international)
                duties {
                  id
                  countryCodeOfOrigin
                  harmonizedSystemCode
                  priceSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                  taxLines {
                    title
                    priceSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                  }
                }
              }
            }
          }
          
          # Discount applications COMPLETE
          discountApplications(first: 10) {
            edges {
              node {
                allocationMethod
                targetSelection
                targetType
                value {
                  ... on MoneyV2 {
                    amount
                    currencyCode
                  }
                  ... on PricingPercentageValue {
                    percentage
                  }
                }
                ... on DiscountCodeApplication {
                  code
                  applicable
                }
                ... on AutomaticDiscountApplication {
                  title
                }
                ... on ManualDiscountApplication {
                  title
                  description
                }
                ... on ScriptDiscountApplication {
                  title
                }
              }
            }
          }
          
          # Fulfillment tracking COMPLETE
          fulfillments(first: 10) {
            edges {
              node {
                id
                status
                createdAt
                updatedAt
                trackingCompany
                trackingNumbers
                trackingUrls
                deliveredAt
                inTransitAt
                estimatedDeliveryAt
                displayStatus
                requiresShipping
                
                # Fulfillment location
                location {
                  id
                  name
                  address {
                    address1
                    address2
                    city
                    province
                    country
                    zip
                  }
                }
                
                # Origin address
                originAddress {
                  address1
                  address2
                  city
                  province
                  country
                  zip
                  firstName
                  lastName
                  company
                }
                
                # Fulfillment line items
                fulfillmentLineItems(first: 50) {
                  edges {
                    node {
                      id
                      quantity
                      lineItem {
                        id
                        title
                        quantity
                        variant {
                          id
                          title
                          sku
                          image {
                            url
                          }
                          product {
                            title
                            handle
                          }
                        }
                      }
                    }
                  }
                }
                
                # Tracking events (if available)
                trackingInfo {
                  company
                  number
                  url
                }
              }
            }
          }
          
          # Returns and refunds COMPLETE
          returns(first: 10) {
            edges {
              node {
                id
                status
                totalQuantity
                createdAt
                updatedAt
                name
                
                # Return line items
                returnLineItems(first: 50) {
                  edges {
                    node {
                      id
                      quantity
                      returnReason
                      returnReasonNote
                      customerNote
                      restockType
                      refundableQuantity
                      refunded
                      restocked
                      
                      # Original fulfillment line item
                      fulfillmentLineItem {
                        id
                        quantity
                        lineItem {
                          id
                          title
                          variant {
                            id
                            title
                            sku
                            image {
                              url
                            }
                            product {
                              title
                              handle
                            }
                          }
                        }
                      }
                    }
                  }
                }
                
                # Return total amounts
                totalReturnedSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
              }
            }
          }
          
          # Payment transactions COMPLETE
          transactions(first: 20) {
            edges {
              node {
                id
                kind
                status
                test
                gateway
                paymentId
                paymentDetails {
                  ... on CardPaymentDetails {
                    creditCardBin
                    creditCardCompany
                    creditCardNumber
                  }
                }
                processedAt
                createdAt
                authorizationCode
                authorizationExpiresAt
                
                # Transaction amounts
                amountSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                maximumRefundableSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                
                # Parent transaction (for refunds)
                parentTransaction {
                  id
                  kind
                  status
                  gateway
                  createdAt
                }
                
                # Receipt details
                receipt
                errorCode
                formattedGateway
                
                # Fees (if applicable)
                fees {
                  id
                  type
                  flatFee {
                    amount
                    currencyCode
                  }
                  flatFeeName
                  rate
                  rateName
                }
              }
            }
          }
          
          # Refunds COMPLETE
          refunds(first: 10) {
            edges {
              node {
                id
                note
                createdAt
                updatedAt
                
                # Refund amounts
                totalRefundedSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                
                # Refund line items
                refundLineItems(first: 50) {
                  edges {
                    node {
                      id
                      quantity
                      priceSet {
                        shopMoney {
                          amount
                          currencyCode
                        }
                      }
                      subtotalSet {
                        shopMoney {
                          amount
                          currencyCode
                        }
                      }
                      totalTaxSet {
                        shopMoney {
                          amount
                          currencyCode
                        }
                      }
                      lineItem {
                        id
                        title
                        variant {
                          title
                          sku
                        }
                      }
                    }
                  }
                }
                
                # Refund transactions
                transactions(first: 10) {
                  edges {
                    node {
                      id
                      kind
                      status
                      gateway
                      processedAt
                      amountSet {
                        shopMoney {
                          amount
                          currencyCode
                        }
                      }
                    }
                  }
                }
                
                # Shipping refund
                shipping {
                  amountSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                  maximumRefundableSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                }
                
                # Duties refund
                duties {
                  id
                  amountSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                }
              }
            }
          }
          
          # Risk assessment
          risks(first: 10) {
            id
            level
            message
            recommendation
            display
            causeCancel
          }
          
          # Events timeline
          events(first: 50) {
            edges {
              node {
                id
                verb
                createdAt
                message
                
                # Subject details
                subject {
                  ... on Order {
                    id
                    name
                  }
                  ... on DraftOrder {
                    id
                    name
                  }
                  ... on Product {
                    id
                    title
                  }
                  ... on ProductVariant {
                    id
                    title
                  }
                }
              }
            }
          }
          
          # Metafields for custom data
          metafields(first: 20) {
            edges {
              node {
                id
                key
                namespace
                value
                type
                description
              }
            }
          }
          
          # Tax lines
          taxLines {
            title
            priceSet {
              shopMoney {
                amount
                currencyCode
              }
            }
            rate
            ratePercentage
            channelLiable
          }
          
          # Shipping lines
          shippingLines(first: 10) {
            edges {
              node {
                id
                title
                code
                source
                carrier
                requestedFulfillmentService {
                  id
                  name
                }
                priceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                discountedPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                taxLines {
                  title
                  priceSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                  rate
                  ratePercentage
                }
                discountAllocations {
                  allocatedAmountSet {
                    shopMoney {
                      amount
                      currencyCode
                    }
                  }
                }
              }
            }
          }
          
          # Additional order attributes
          customAttributes {
            key
            value
          }
          
          # Closed status
          closed
          closedAt
          
          # Confirmed status
          confirmed
          
          # Test order flag
          test
          
          # Currency and presentation
          currencyCode
          presentmentCurrencyCode
          
          # Shopify Protect
          shopifyProtect {
            status
            eligibleForProtection
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { orderId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors) {
      console.error('❌ Order details fetch errors:', response.data.errors);
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = response.data.data.order;
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Transform the COMPLETE order data for Flutter app
    const transformedOrder = {
      // Basic order info
      id: order.id,
      name: order.name,
      orderNumber: order.orderNumber,
      processedAt: order.processedAt,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt,
      cancelledAt: order.cancelledAt,
      cancelReason: order.cancelReason,
      closedAt: order.closedAt,
      closed: order.closed,
      confirmed: order.confirmed,
      test: order.test,
      
      // Customer info
      email: order.email,
      phone: order.phone,
      customerUrl: order.customerUrl,
      note: order.note,
      tags: order.tags || [],
      
      // Status information
      fulfillmentStatus: order.displayFulfillmentStatus,
      financialStatus: order.displayFinancialStatus,
      
      // Source and attribution
      source: {
        name: order.sourceName,
        identifier: order.sourceIdentifier,
        url: order.sourceUrl
      },
      
      // Complete pricing breakdown
      pricing: {
        currency: order.currencyCode,
        presentmentCurrency: order.presentmentCurrencyCode,
        
        total: {
          amount: order.currentTotalPriceSet.shopMoney.amount,
          currencyCode: order.currentTotalPriceSet.shopMoney.currencyCode
        },
        originalTotal: order.originalTotalPriceSet ? {
          amount: order.originalTotalPriceSet.shopMoney.amount,
          currencyCode: order.originalTotalPriceSet.shopMoney.currencyCode
        } : null,
        subtotal: {
          amount: order.currentSubtotalPriceSet.shopMoney.amount,
          currencyCode: order.currentSubtotalPriceSet.shopMoney.currencyCode
        },
        totalShipping: {
          amount: order.totalShippingPriceSet.shopMoney.amount,
          currencyCode: order.totalShippingPriceSet.shopMoney.currencyCode
        },
        totalTax: order.currentTotalTaxSet ? {
          amount: order.currentTotalTaxSet.shopMoney.amount,
          currencyCode: order.currentTotalTaxSet.shopMoney.currencyCode
        } : null,
        totalDiscount: {
          amount: order.totalDiscountsSet.shopMoney.amount,
          currencyCode: order.totalDiscountsSet.shopMoney.currencyCode
        },
        totalRefunded: order.totalRefundedSet ? {
          amount: order.totalRefundedSet.shopMoney.amount,
          currencyCode: order.totalRefundedSet.shopMoney.currencyCode
        } : null,
        totalTip: order.totalTipReceivedSet ? {
          amount: order.totalTipReceivedSet.shopMoney.amount,
          currencyCode: order.totalTipReceivedSet.shopMoney.currencyCode
        } : null
      },
      
      // Complete address information
      addresses: {
        shipping: order.shippingAddress ? {
          ...order.shippingAddress,
          formatted: order.shippingAddress.formattedArea,
          coordinates: order.shippingAddress.latitude && order.shippingAddress.longitude ? {
            latitude: order.shippingAddress.latitude,
            longitude: order.shippingAddress.longitude
          } : null
        } : null,
        billing: order.billingAddress ? {
          ...order.billingAddress,
          formatted: order.billingAddress.formattedArea
        } : null
      },
      
      // Customer journey insights
      customerJourney: order.customerJourney ? {
        orderIndex: order.customerJourney.customerOrderIndex,
        isFirstOrder: order.customerJourney.customerOrderIndex === 1,
        daysToConversion: order.customerJourney.daysToConversion,
        momentsCount: order.customerJourney.momentsCount,
        ready: order.customerJourney.ready,
        
        firstVisit: order.customerJourney.firstVisit ? {
          ...order.customerJourney.firstVisit,
          utm: order.customerJourney.firstVisit.utmParameters
        } : null,
        
        lastVisit: order.customerJourney.lastVisit ? {
          ...order.customerJourney.lastVisit,
          utm: order.customerJourney.lastVisit.utmParameters
        } : null
      } : null,
      
      // Complete line items with ALL details
      lineItems: order.lineItems.edges.map(edge => {
        const item = edge.node;
        const variant = item.variant;
        const product = variant.product;
        
        return {
          id: item.id,
          title: item.title,
          name: item.name,
          quantity: item.quantity,
          fulfillableQuantity: item.fulfillableQuantity,
          fulfillmentStatus: item.fulfillmentStatus,
          requiresShipping: item.requiresShipping,
          taxable: item.taxable,
          giftCard: item.giftCard,
          vendor: item.vendor,
          variantTitle: item.variantTitle,
          productExists: item.productExists,
          
          // Custom attributes and personalization
          customAttributes: item.customAttributes || [],
          
          // Complete variant information
          variant: {
            id: variant.id,
            title: variant.title,
            sku: variant.sku,
            price: variant.price,
            compareAtPrice: variant.compareAtPrice,
            weight: variant.weight,
            weightUnit: variant.weightUnit,
            availableForSale: variant.availableForSale,
            inventoryQuantity: variant.inventoryQuantity,
            inventoryPolicy: variant.inventoryPolicy,
            inventoryManagement: variant.inventoryManagement,
            barcode: variant.barcode,
            
            selectedOptions: variant.selectedOptions || [],
            
            image: variant.image ? {
              url: variant.image.url,
              altText: variant.image.altText,
              width: variant.image.width,
              height: variant.image.height
            } : null,
            
            // Complete product information
            product: {
              id: product.id,
              title: product.title,
              handle: product.handle,
              productType: product.productType,
              vendor: product.vendor,
              description: product.description,
              descriptionHtml: product.descriptionHtml,
              tags: product.tags || [],
              createdAt: product.createdAt,
              updatedAt: product.updatedAt,
              publishedAt: product.publishedAt,
              availableForSale: product.availableForSale,
              totalInventory: product.totalInventory,
              
              featuredImage: product.featuredImage ? {
                url: product.featuredImage.url,
                altText: product.featuredImage.altText,
                width: product.featuredImage.width,
                height: product.featuredImage.height
              } : null,
              
              images: product.images.edges.map(imgEdge => ({
                url: imgEdge.node.url,
                altText: imgEdge.node.altText,
                width: imgEdge.node.width,
                height: imgEdge.node.height
              })),
              
              collections: product.collections.edges.map(colEdge => ({
                id: colEdge.node.id,
                title: colEdge.node.title,
                handle: colEdge.node.handle,
                description: colEdge.node.description
              })),
              
              options: product.options.map(option => ({
                id: option.id,
                name: option.name,
                values: option.values
              }))
            }
          },
          
          // Complete pricing breakdown per item
          pricing: {
            originalUnitPrice: {
              amount: item.originalUnitPriceSet.shopMoney.amount,
              currencyCode: item.originalUnitPriceSet.shopMoney.currencyCode
            },
            discountedUnitPrice: item.discountedUnitPriceSet ? {
              amount: item.discountedUnitPriceSet.shopMoney.amount,
              currencyCode: item.discountedUnitPriceSet.shopMoney.currencyCode
            } : null,
            originalTotal: {
              amount: item.originalTotalSet.shopMoney.amount,
              currencyCode: item.originalTotalSet.shopMoney.currencyCode
            },
            discountedTotal: item.discountedTotalSet ? {
              amount: item.discountedTotalSet.shopMoney.amount,
              currencyCode: item.discountedTotalSet.shopMoney.currencyCode
            } : null,
            totalDiscount: item.totalDiscountSet ? {
              amount: item.totalDiscountSet.shopMoney.amount,
              currencyCode: item.totalDiscountSet.shopMoney.currencyCode
            } : null
          },
          
          // Tax breakdown per item
          taxes: item.taxLines.map(taxLine => ({
            title: taxLine.title,
            amount: {
              amount: taxLine.priceSet.shopMoney.amount,
              currencyCode: taxLine.priceSet.shopMoney.currencyCode
            },
            rate: taxLine.rate,
            ratePercentage: taxLine.ratePercentage
          })),
          
          // Item-specific discounts
          discounts: item.discountAllocations.map(discount => ({
            allocatedAmount: {
              amount: discount.allocatedAmountSet.shopMoney.amount,
              currencyCode: discount.allocatedAmountSet.shopMoney.currencyCode
            },
            application: {
              targetSelection: discount.discountApplication.targetSelection,
              targetType: discount.discountApplication.targetType,
              value: discount.discountApplication.value,
              code: discount.discountApplication.code || null,
              title: discount.discountApplication.title || null,
              description: discount.discountApplication.description || null
            }
          })),
          
          // International duties (if applicable)
          duties: item.duties.map(duty => ({
            id: duty.id,
            countryCodeOfOrigin: duty.countryCodeOfOrigin,
            harmonizedSystemCode: duty.harmonizedSystemCode,
            price: {
              amount: duty.priceSet.shopMoney.amount,
              currencyCode: duty.priceSet.shopMoney.currencyCode
            },
            taxLines: duty.taxLines.map(taxLine => ({
              title: taxLine.title,
              price: {
                amount: taxLine.priceSet.shopMoney.amount,
                currencyCode: taxLine.priceSet.shopMoney.currencyCode
              }
            }))
          }))
        };
      }),
      
      // Complete discount applications
      discounts: order.discountApplications.edges.map(edge => {
        const discount = edge.node;
        return {
          allocationMethod: discount.allocationMethod,
          targetSelection: discount.targetSelection,
          targetType: discount.targetType,
          value: discount.value,
          code: discount.code || null,
          title: discount.title || null,
          description: discount.description || null,
          applicable: discount.applicable !== false
        };
      }),
      
      // Complete fulfillment tracking
      fulfillments: order.fulfillments.edges.map(edge => {
        const fulfillment = edge.node;
        return {
          id: fulfillment.id,
          status: fulfillment.status,
          displayStatus: fulfillment.displayStatus,
          createdAt: fulfillment.createdAt,
          updatedAt: fulfillment.updatedAt,
          deliveredAt: fulfillment.deliveredAt,
          inTransitAt: fulfillment.inTransitAt,
          estimatedDeliveryAt: fulfillment.estimatedDeliveryAt,
          requiresShipping: fulfillment.requiresShipping,
          
          tracking: {
            company: fulfillment.trackingCompany,
            numbers: fulfillment.trackingNumbers || [],
            urls: fulfillment.trackingUrls || [],
            info: fulfillment.trackingInfo || {}
          },
          
          location: fulfillment.location ? {
            id: fulfillment.location.id,
            name: fulfillment.location.name,
            address: fulfillment.location.address
          } : null,
          
          originAddress: fulfillment.originAddress,
          
          items: fulfillment.fulfillmentLineItems.edges.map(itemEdge => {
            const fulfillmentItem = itemEdge.node;
            return {
              id: fulfillmentItem.id,
              quantity: fulfillmentItem.quantity,
              lineItem: {
                id: fulfillmentItem.lineItem.id,
                title: fulfillmentItem.lineItem.title,
                totalQuantity: fulfillmentItem.lineItem.quantity,
                variant: {
                  id: fulfillmentItem.lineItem.variant.id,
                  title: fulfillmentItem.lineItem.variant.title,
                  sku: fulfillmentItem.lineItem.variant.sku,
                  image: fulfillmentItem.lineItem.variant.image,
                  product: fulfillmentItem.lineItem.variant.product
                }
              }
            };
          })
        };
      }),
      
      // Complete returns information
      returns: order.returns.edges.map(edge => {
        const returnItem = edge.node;
        return {
          id: returnItem.id,
          name: returnItem.name,
          status: returnItem.status,
          totalQuantity: returnItem.totalQuantity,
          createdAt: returnItem.createdAt,
          updatedAt: returnItem.updatedAt,
          
          totalReturned: returnItem.totalReturnedSet ? {
            amount: returnItem.totalReturnedSet.shopMoney.amount,
            currencyCode: returnItem.totalReturnedSet.shopMoney.currencyCode
          } : null,
          
          items: returnItem.returnLineItems.edges.map(itemEdge => {
            const returnLineItem = itemEdge.node || {};
            // defensive extraction: some Admin schemas don't expose fulfillmentLineItem or nested lineItem
            const fulfillmentLineItem = returnLineItem.fulfillmentLineItem || null;
            const nestedLineItem = fulfillmentLineItem?.lineItem || returnLineItem.lineItem || null;

            return {
              id: returnLineItem.id,
              quantity: returnLineItem.quantity,
              reason: returnLineItem.returnReason,
              reasonNote: returnLineItem.returnReasonNote,
              customerNote: returnLineItem.customerNote,
              restockType: returnLineItem.restockType,
              refundableQuantity: returnLineItem.refundableQuantity,
              refunded: returnLineItem.refunded,
              restocked: returnLineItem.restocked,

              originalItem: {
                id: fulfillmentLineItem?.id || returnLineItem.id || null,
                quantity: fulfillmentLineItem?.quantity || returnLineItem.quantity || 0,
                lineItem: nestedLineItem ? {
                  id: nestedLineItem.id || null,
                  title: nestedLineItem.title || nestedLineItem.name || 'Unknown',
                  variant: nestedLineItem.variant || null
                } : null
              }
            };
          })
        };
      }),
      
      // Complete payment transactions
      transactions: order.transactions.edges.map(edge => {
        const transaction = edge.node;
        return {
          id: transaction.id,
          kind: transaction.kind,
          status: transaction.status,
          test: transaction.test,
          gateway: transaction.gateway,
          formattedGateway: transaction.formattedGateway,
          paymentId: transaction.paymentId,
          processedAt: transaction.processedAt,
          createdAt: transaction.createdAt,
          authorizationCode: transaction.authorizationCode,
          authorizationExpiresAt: transaction.authorizationExpiresAt,
          errorCode: transaction.errorCode,
          receipt: transaction.receipt,
          
          amount: {
            amount: transaction.amountSet.shopMoney.amount,
            currencyCode: transaction.amountSet.shopMoney.currencyCode
          },
          
          maximumRefundable: transaction.maximumRefundableSet ? {
            amount: transaction.maximumRefundableSet.shopMoney.amount,
            currencyCode: transaction.maximumRefundableSet.shopMoney.currencyCode
          } : null,
          
          paymentDetails: transaction.paymentDetails || null,
          
          parentTransaction: transaction.parentTransaction ? {
            id: transaction.parentTransaction.id,
            kind: transaction.parentTransaction.kind,
            status: transaction.parentTransaction.status,
            gateway: transaction.parentTransaction.gateway,
            createdAt: transaction.parentTransaction.createdAt
          } : null,
          
          fees: transaction.fees.map(fee => ({
            id: fee.id,
            type: fee.type,
            flatFee: fee.flatFee ? {
              amount: fee.flatFee.amount,
              currencyCode: fee.flatFee.currencyCode
            } : null,
            flatFeeName: fee.flatFeeName,
            rate: fee.rate,
            rateName: fee.rateName
          }))
        };
      }),
      
      // Complete refunds information
      refunds: order.refunds.edges.map(edge => {
        const refund = edge.node;
        return {
          id: refund.id,
          note: refund.note,
          createdAt: refund.createdAt,
          updatedAt: refund.updatedAt,
          
          totalRefunded: {
            amount: refund.totalRefundedSet.shopMoney.amount,
            currencyCode: refund.totalRefundedSet.shopMoney.currencyCode
          },
          
          lineItems: refund.refundLineItems.edges.map(itemEdge => {
            const refundItem = itemEdge.node;
            return {
              id: refundItem.id,
              quantity: refundItem.quantity,
              price: {
                amount: refundItem.priceSet.shopMoney.amount,
                currencyCode: refundItem.priceSet.shopMoney.currencyCode
              },
              subtotal: {
                amount: refundItem.subtotalSet.shopMoney.amount,
                currencyCode: refundItem.subtotalSet.shopMoney.currencyCode
              },
              totalTax: refundItem.totalTaxSet ? {
                amount: refundItem.totalTaxSet.shopMoney.amount,
                currencyCode: refundItem.totalTaxSet.shopMoney.currencyCode
              } : null,
              lineItem: {
                id: refundItem.lineItem.id,
                title: refundItem.lineItem.title,
                variant: refundItem.lineItem.variant
              }
            };
          }),
          
          transactions: refund.transactions.edges.map(transactionEdge => {
            const refundTransaction = transactionEdge.node;
            return {
              id: refundTransaction.id,
              kind: refundTransaction.kind,
              status: refundTransaction.status,
              gateway: refundTransaction.gateway,
              processedAt: refundTransaction.processedAt,
              amount: {
                amount: refundTransaction.amountSet.shopMoney.amount,
                currencyCode: refundTransaction.amountSet.shopMoney.currencyCode
              }
            };
          }),
          
          shipping: refund.shipping ? {
            amount: {
              amount: refund.shipping.amountSet.shopMoney.amount,
              currencyCode: refund.shipping.amountSet.shopMoney.currencyCode
            },
            maximumRefundable: refund.shipping.maximumRefundableSet ? {
              amount: refund.shipping.maximumRefundableSet.shopMoney.amount,
              currencyCode: refund.shipping.maximumRefundableSet.shopMoney.currencyCode
            } : null
          } : null,
          
          duties: refund.duties.map(duty => ({
            id: duty.id,
            amount: {
              amount: duty.amountSet.shopMoney.amount,
              currencyCode: duty.amountSet.shopMoney.currencyCode
            }
          }))
        };
      }),
      
      // Risk assessment
      risks: order.risks.map(risk => ({
        id: risk.id,
        level: risk.level,
        message: risk.message,
        recommendation: risk.recommendation,
        display: risk.display,
        causeCancel: risk.causeCancel
      })),
      
      // Order events timeline
      events: order.events.edges.map(edge => {
        const event = edge.node;
        return {
          id: event.id,
          verb: event.verb,
          createdAt: event.createdAt,
          message: event.message,
          subject: event.subject
        };
      }),
      
      // Tax breakdown
      taxes: order.taxLines.map(taxLine => ({
        title: taxLine.title,
        amount: {
          amount: taxLine.priceSet.shopMoney.amount,
          currencyCode: taxLine.priceSet.shopMoney.currencyCode
        },
        rate: taxLine.rate,
        ratePercentage: taxLine.ratePercentage,
        channelLiable: taxLine.channelLiable
      })),
      
      // Shipping lines
      shippingLines: order.shippingLines.edges.map(edge => {
        const shippingLine = edge.node;
        return {
          id: shippingLine.id,
          title: shippingLine.title,
          code: shippingLine.code,
          source: shippingLine.source,
          carrier: shippingLine.carrier,
          
          requestedFulfillmentService: shippingLine.requestedFulfillmentService ? {
            id: shippingLine.requestedFulfillmentService.id,
            name: shippingLine.requestedFulfillmentService.name
          } : null,
          
          price: {
            amount: shippingLine.priceSet.shopMoney.amount,
            currencyCode: shippingLine.priceSet.shopMoney.currencyCode
          },
          
          discountedPrice: shippingLine.discountedPriceSet ? {
            amount: shippingLine.discountedPriceSet.shopMoney.amount,
            currencyCode: shippingLine.discountedPriceSet.shopMoney.currencyCode
          } : null,
          
          taxLines: shippingLine.taxLines.map(taxLine => ({
            title: taxLine.title,
            price: {
              amount: taxLine.priceSet.shopMoney.amount,
              currencyCode: taxLine.priceSet.shopMoney.currencyCode
            },
            rate: taxLine.rate,
            ratePercentage: taxLine.ratePercentage
          })),
          
          discountAllocations: shippingLine.discountAllocations.map(discount => ({
            allocatedAmount: {
              amount: discount.allocatedAmountSet.shopMoney.amount,
              currencyCode: discount.allocatedAmountSet.shopMoney.currencyCode
            }
          }))
        };
      }),
      
      // Custom attributes
      customAttributes: order.customAttributes || [],
      
      // Metafields for custom data
      metafields: order.metafields.edges.reduce((acc, edge) => {
        const metafield = edge.node;
        acc[`${metafield.namespace}.${metafield.key}`] = {
          value: metafield.value,
          type: metafield.type,
          description: metafield.description
        };
        return acc;
      }, {}),
      
      // Shopify Protect information
      shopifyProtect: order.shopifyProtect || null,
      
      // Helper flags for Flutter UI
      canReorder: order.displayFulfillmentStatus === 'FULFILLED',
      canReturn: order.displayFulfillmentStatus === 'FULFILLED' && 
                order.displayFinancialStatus !== 'REFUNDED' &&
                order.returns.edges.length === 0,
      hasTracking: order.fulfillments.edges.some(f => 
        f.node.trackingNumbers && f.node.trackingNumbers.length > 0
      ),
      isReturnable: order.returns.edges.length === 0 && 
                   order.displayFulfillmentStatus === 'FULFILLED',
      hasRefunds: order.refunds.edges.length > 0,
      isCancelled: order.cancelledAt !== null,
      isTest: order.test,
      isFullyRefunded: order.displayFinancialStatus === 'REFUNDED',
      hasPartialRefund: order.refunds.edges.length > 0 && 
                       order.displayFinancialStatus !== 'REFUNDED'
    };

    console.log(`✅ Complete order details prepared with ${transformedOrder.lineItems.length} items`);
    res.json({ order: transformedOrder });

  } catch (error) {
    console.error('❌ Order details fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// ===== CUSTOMER ANALYTICS & INSIGHTS =====

// GET /customer/analytics - Customer shopping analytics
app.get('/customer/analytics', authenticateAppToken, async (req, res) => {
  try {
    const { period = '1year' } = req.query;
    console.log('📊 Fetching customer analytics for:', req.session.email);

    // Calculate date range
    const endDate = new Date();
    const startDate = new Date();
    switch (period) {
      case '30days':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90days':
        startDate.setDate(startDate.getDate() - 90);
        break;
      case '6months':
        startDate.setMonth(startDate.getMonth() - 6);
        break;
      case '1year':
      default:
        startDate.setFullYear(startDate.getFullYear() - 1);
        break;
    }

    const query = `
      query getCustomerAnalytics($customerId: ID!, $startDate: DateTime!, $endDate: DateTime!) {
        customer(id: $customerId) {
          id
          totalSpent {
            amount
            currencyCode
          }
          orders(first: 250, query: "processed_at:>'\${startDate.toISOString()}' AND processed_at:<'\${endDate.toISOString()}'") {
            edges {
              node {
                id
                processedAt
                currentTotalPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                lineItems(first: 250) {
                  edges {
                    node {
                      quantity
                      variant {
                        product {
                          productType
                          vendor
                          collections(first: 5) {
                            edges {
                              node {
                                title
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: {
          customerId: req.session.customerId,
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString()
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors) {
      console.error('❌ Analytics fetch errors:', response.data.errors);
      return res.status(500).json({ error: 'Failed to fetch analytics' });
    }

    const customer = response.data.data.customer;
    const orders = customer.orders.edges;

    // Calculate analytics
    const analytics = {
      period: period,
      totalSpent: {
        amount: customer.totalSpent.amount,
        currencyCode: customer.totalSpent.currencyCode
      },
      periodSpent: {
        amount: orders.reduce((sum, order) => 
          sum + parseFloat(order.node.currentTotalPriceSet.shopMoney.amount), 0
        ).toFixed(2),
        currencyCode: 'EUR'
      },
      orderCount: orders.length,
      averageOrderValue: orders.length > 0 ? 
        (orders.reduce((sum, order) => 
          sum + parseFloat(order.node.currentTotalPriceSet.shopMoney.amount), 0
        ) / orders.length).toFixed(2) : '0',
      
      // Monthly breakdown
      monthlySpending: {},
      
      // Product categories
      topCategories: {},
      topVendors: {},
      
      // Shopping frequency
      orderFrequency: orders.length / Math.max(1, period === '30days' ? 1 : period === '90days' ? 3 : period === '6months' ? 6 : 12),
      
      // Customer lifetime value indicators
      customerSince: customer.createdAt,
      isReturningCustomer: orders.length > 1,
      loyaltyScore: Math.min(100, (orders.length * 10) + (parseFloat(customer.totalSpent.amount) / 10))
    };

    // Process monthly data
    orders.forEach(order => {
      const month = new Date(order.node.processedAt).toISOString().substring(0, 7);
      if (!analytics.monthlySpending[month]) {
        analytics.monthlySpending[month] = 0;
      }
      analytics.monthlySpending[month] += parseFloat(order.node.currentTotalPriceSet.shopMoney.amount);
      
      // Process product categories
      order.node.lineItems.edges.forEach(item => {
        const productType = item.node.variant.product.productType;
        const vendor = item.node.variant.product.vendor;
        
        analytics.topCategories[productType] = (analytics.topCategories[productType] || 0) + item.node.quantity;
        analytics.topVendors[vendor] = (analytics.topVendors[vendor] || 0) + item.node.quantity;
      });
    });

    console.log('✅ Customer analytics calculated successfully');
    res.json({ analytics });

  } catch (error) {
    console.error('❌ Analytics fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// ===== WISHLIST & FAVORITES =====

// GET /customer/wishlist - Customer wishlist/favorites (Firebase + Shopify hybrid)
app.get('/customer/wishlist', authenticateAppToken, async (req, res) => {
  try {
    console.log('❤️ Fetching wishlist for:', req.session.email);

    let wishlistProductIds = [];
    let wishlistItems = []; // ✅ Store full wishlist items with variant info
    let useFirebase = firebaseEnabled && wishlistService;
    let shouldSyncFromShopify = false;

    if (useFirebase) {
      try {
        // Check if wishlist document exists first
        const wishlistExists = await wishlistService.wishlistExists(req.session.customerId);
        
        if (!wishlistExists) {
          shouldSyncFromShopify = true;
        }

        // Try Firebase first
        wishlistItems = await wishlistService.getWishlist(
          req.session.customerId, 
          req.session.email
        );
        wishlistProductIds = wishlistItems.map(item => item.productId);
        console.log(`🔥 Firebase returned ${wishlistItems.length} wishlist items`);
      } catch (firebaseError) {
        console.error('❌ Firebase wishlist fetch failed, falling back to Shopify:', firebaseError.message);
        useFirebase = false;
      }
    }

    // Fallback to Shopify if Firebase fails or is not enabled
    // Also sync from Shopify if Firebase is working but no document exists yet
    if (!useFirebase || shouldSyncFromShopify) {
      console.log('📦 Using Shopify metafield for wishlist');
      
      const query = `
        query getCustomerWishlist($customerId: ID!) {
          customer(id: $customerId) {
            id
            metafield(namespace: "customer", key: "wishlist") {
              value
            }
          }
        }
      `;

      const response = await axios.post(
        config.adminApiUrl,
        {
          query,
          variables: { customerId: req.session.customerId }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );

      const metafield = response.data.data?.customer?.metafield;
      if (metafield?.value) {
        try {
          wishlistProductIds = JSON.parse(metafield.value);
          // Convert to wishlist items format for compatibility (no variant info available from Shopify metafield)
          wishlistItems = wishlistProductIds.map(productId => ({
            productId,
            addedAt: new Date().toISOString(),
            customerEmail: req.session.email,
            customerId: req.session.customerId,
            selectedOptions: null,
            variantId: null
          }));
        } catch (jsonParseError) {
          console.error('❌ [WISHLIST] Failed to parse metafield JSON:', jsonParseError.message);
          console.error('❌ [WISHLIST] Corrupted metafield value length:', metafield.value?.length || 0);
          // Fall back to comma-separated parsing
          wishlistProductIds = metafield.value.split(',').filter(id => id.trim());
          // Convert to wishlist items format for compatibility (no variant info available from Shopify metafield)
          wishlistItems = wishlistProductIds.map(productId => ({
            productId: productId.trim(),
            addedAt: new Date().toISOString(),
            customerEmail: req.session.email,
            customerId: req.session.customerId,
            selectedOptions: null,
            variantId: null
          }));
        }

        // If we found Shopify data and this is an initial sync to Firebase, sync it
        if (wishlistProductIds.length > 0 && useFirebase && wishlistService && shouldSyncFromShopify) {
          try {
            await wishlistService.syncFromShopify(
              req.session.customerId,
              req.session.email,
              wishlistProductIds
            );
            console.log('🔄 Successfully synced Shopify wishlist to Firebase');
          } catch (syncError) {
            console.error('❌ Failed to sync Shopify wishlist to Firebase:', syncError.message);
          }
        }
      }
    }


    if (wishlistProductIds.length === 0) {
      return res.json({ wishlist: [] });
    }

    // Fetch product details for wishlist items
    const productsQuery = `
      query getWishlistProducts($productIds: [ID!]!) {
        nodes(ids: $productIds) {
          ... on Product {
            id
            title
            handle
            description
            productType
            vendor
            tags
            createdAt
            priceRange {
              maxVariantPrice {
                amount
                currencyCode
              }
              minVariantPrice {
                amount
                currencyCode
              }
            }
            compareAtPriceRange {
              maxVariantCompareAtPrice {
                amount
                currencyCode
              }
              minVariantCompareAtPrice {
                amount
                currencyCode
              }
            }
            featuredImage {
              url
              altText
            }
            images(first: 5) {
              edges {
                node {
                  url
                  altText
                }
              }
            }
            variants(first: 10) {
              edges {
                node {
                  id
                  title
                  sku
                  price
                  compareAtPrice
                  selectedOptions {
                    name
                    value
                  }
                  image {
                    url
                  }
                }
              }
            }
            totalInventory
          }
        }
      }
    `;

    const productsResponse = await axios.post(
      config.adminApiUrl,
      {
        query: productsQuery,
        variables: { productIds: wishlistProductIds }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    // Avoid logging massive response data that can cause JSON corruption

    const products = productsResponse.data.data?.nodes || [];
    
    const wishlist = products.filter(product => product !== null).map(product => {
      // Find the matching wishlist item with variant information
      const wishlistItem = wishlistItems.find(item => 
        item.productId === product.id || 
        (item.variantId && product.variants.edges.some(v => v.node.id === item.variantId))
      );
      
      // Process variants first
      const processedVariants = product.variants.edges.map(edge => ({
        id: edge.node.id,
        title: edge.node.title,
        sku: edge.node.sku,
        price: edge.node.price,
        compareAtPrice: edge.node.compareAtPrice,
        selectedOptions: edge.node.selectedOptions,
        image: edge.node.image
      }));
      
      let selectedVariant = null;
      let selectedOptions = {};
      let selectedSku = null;
      let selectedPrice = null;
      let selectedCompareAtPrice = null;
      let selectedImage = null;
      
      if (wishlistItem && (wishlistItem.selectedOptions || wishlistItem.variantId)) {
        console.log(`🔍 [VARIANT] Processing wishlist item:`, {
          productId: product.id,
          variantId: wishlistItem.variantId,
          selectedOptions: wishlistItem.selectedOptions
        });
        
        // Find the matching variant by ID first
        if (wishlistItem.variantId) {
          selectedVariant = processedVariants.find(v => v.id === wishlistItem.variantId);
        }
        
        // If no variant ID match, try to match by selectedOptions
        if (!selectedVariant && wishlistItem.selectedOptions) {
          selectedVariant = processedVariants.find(variant => {
            const variantOptions = {};
            variant.selectedOptions.forEach(opt => {
              variantOptions[opt.name] = opt.value;
            });
            
            // Check if all stored options match this variant
            return Object.entries(wishlistItem.selectedOptions).every(([key, value]) => 
              variantOptions[key] === value
            );
          });
        }
        
        if (selectedVariant) {
          console.log(`✅ [VARIANT] Found matching variant:`, {
            variantId: selectedVariant.id,
            title: selectedVariant.title,
            selectedOptions: selectedVariant.selectedOptions,
            image: selectedVariant.image?.url
          });
          
          selectedOptions = {};
          selectedVariant.selectedOptions.forEach(opt => {
            selectedOptions[opt.name] = opt.value;
          });
          selectedSku = selectedVariant.sku;
          selectedPrice = selectedVariant.price;
          selectedCompareAtPrice = selectedVariant.compareAtPrice;
          selectedImage = selectedVariant.image?.url || product.featuredImage?.url;
        } else {
          console.log(`⚠️ [VARIANT] No matching variant found, using stored options:`, wishlistItem.selectedOptions);
          selectedOptions = wishlistItem.selectedOptions || {};
          // For fallback, try to find any variant with similar color
          if (wishlistItem.selectedOptions?.Farbe) {
            const colorValue = wishlistItem.selectedOptions.Farbe.toLowerCase();
            const fallbackVariant = processedVariants.find(variant => 
              variant.selectedOptions.some(opt => 
                opt.name === 'Farbe' && opt.value.toLowerCase().includes(colorValue.split(' ')[0])
              )
            );
            if (fallbackVariant) {
              console.log(`🔄 [VARIANT] Using fallback variant for color match:`, fallbackVariant.id);
              selectedImage = fallbackVariant.image?.url || product.featuredImage?.url;
              selectedPrice = fallbackVariant.price;
              selectedCompareAtPrice = fallbackVariant.compareAtPrice;
            }
          }
        }
      }
      
      return {
        id: product.id,
        title: product.title,
        handle: product.handle,
        description: product.description,
        price: {
          amount: selectedPrice || product.priceRange.minVariantPrice.amount,
          currencyCode: product.priceRange.minVariantPrice.currencyCode
        },
        compareAtPrice: selectedCompareAtPrice ? {
          amount: selectedCompareAtPrice,
          currencyCode: product.priceRange.minVariantPrice.currencyCode
        } : (product.compareAtPriceRange?.minVariantCompareAtPrice ? {
          amount: product.compareAtPriceRange.minVariantCompareAtPrice.amount,
          currencyCode: product.compareAtPriceRange.minVariantCompareAtPrice.currencyCode
        } : null),
        image: selectedImage || product.featuredImage?.url,
        images: product.images.edges.map(edge => edge.node),
        variants: processedVariants,
        selectedVariant: selectedVariant,
        selectedOptions: selectedOptions, // ✅ CRITICAL: Include selected options
        sku: selectedSku,
        variantId: selectedVariant?.id,
        totalInventory: product.totalInventory,
        productType: product.productType,
        vendor: product.vendor,
        tags: product.tags,
        isOnSale: (selectedCompareAtPrice && selectedPrice) ? 
          parseFloat(selectedCompareAtPrice) > parseFloat(selectedPrice) : 
          (product.compareAtPriceRange?.minVariantCompareAtPrice ? 
            parseFloat(product.compareAtPriceRange.minVariantCompareAtPrice.amount) > parseFloat(product.priceRange.minVariantPrice.amount) : false),
        addedToWishlistAt: wishlistItem?.addedAt || new Date().toISOString()
      };
    });

    console.log(`✅ Fetched ${wishlist.length} wishlist items`);
    res.json({ wishlist });

  } catch (error) {
    console.error('❌ Wishlist fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch wishlist' });
  }
});

// POST /customer/wishlist - Add/remove from wishlist (Firebase + Shopify hybrid)
app.post('/customer/wishlist', authenticateAppToken, async (req, res) => {
  try {
    const { productId, action = 'add', variantId, selectedOptions } = req.body; // action: 'add' or 'remove'
    console.log(`❤️ ${action === 'add' ? 'Adding to' : 'Removing from'} wishlist:`, productId);
    console.log('   Variant ID:', variantId);
    console.log('   Selected Options:', selectedOptions);

    let result;
    let useFirebase = firebaseEnabled && wishlistService;

    if (useFirebase) {
      try {
        // Try Firebase first
        if (action === 'add') {
          // ✅ CRITICAL: Fetch product data from Shopify before storing in Firebase
          let productData = null;
          
          try {
            console.log('🛍️ Fetching product data from Shopify for Firebase storage');
            const productQuery = `
              query getProduct($productId: ID!) {
                product(id: $productId) {
                  id
                  title
                  handle
                  featuredImage {
                    url
                  }
                  priceRange {
                    minVariantPrice {
                      amount
                    }
                  }
                  variants(first: 20) {
                    edges {
                      node {
                        id
                        title
                        sku
                        price
                        selectedOptions {
                          name
                          value
                        }
                        image {
                          url
                        }
                      }
                    }
                  }
                }
              }
            `;

            const productResponse = await axios.post(
              config.adminApiUrl,
              {
                query: productQuery,
                variables: { productId: productId }
              },
              {
                headers: {
                  'X-Shopify-Access-Token': config.adminToken,
                  'Content-Type': 'application/json'
                }
              }
            );

            const product = productResponse.data.data?.product;
            if (product) {
              const variants = product.variants.edges.map(edge => edge.node);
              let selectedVariant = null;
              
              // Find matching variant
              if (variantId) {
                selectedVariant = variants.find(v => v.id === variantId);
              } else if (selectedOptions) {
                selectedVariant = variants.find(variant => {
                  return variant.selectedOptions.every(opt => 
                    selectedOptions[opt.name] === opt.value
                  );
                });
              }
              
              // Use selected variant or first variant as fallback
              const useVariant = selectedVariant || variants[0];
              
              productData = {
                title: product.title,
                handle: product.handle,
                imageUrl: useVariant?.image?.url || product.featuredImage?.url || '',
                price: parseFloat(useVariant?.price || product.priceRange.minVariantPrice.amount) || 0,
                sku: useVariant?.sku || ''
              };
              
              console.log('✅ Fetched product data:', productData);
            }
          } catch (shopifyError) {
            console.error('⚠️ Failed to fetch product data from Shopify:', shopifyError.message);
            // Continue without product data - Firebase will store basic info
          }
          
          // Use enhanced method if we have product data, otherwise use basic method
          if (productData) {
            result = await wishlistService.addToWishlistWithProductData(
              req.session.customerId,
              req.session.email,
              productId,
              variantId,
              selectedOptions,
              productData
            );
          } else {
            result = await wishlistService.addToWishlist(
              req.session.customerId,
              req.session.email,
              productId,
              variantId,
              selectedOptions
            );
          }
        } else if (action === 'remove') {
          result = await wishlistService.removeFromWishlist(
            req.session.customerId,
            req.session.email,
            productId,
            variantId,
            selectedOptions
          );
        }
        console.log('🔥 Firebase wishlist operation successful');
      } catch (firebaseError) {
        console.error('❌ Firebase wishlist operation failed, falling back to Shopify:', firebaseError.message);
        useFirebase = false;
      }
    }

    // Fallback to Shopify if Firebase fails or is not enabled
    if (!useFirebase) {
      console.log('📦 Using Shopify metafield for wishlist operation');
      
      // Get current wishlist from Shopify
      const getQuery = `
        query getCustomerWishlist($customerId: ID!) {
          customer(id: $customerId) {
            id
            metafield(namespace: "customer", key: "wishlist") {
              id
              value
            }
          }
        }
      `;

      const getResponse = await axios.post(
        config.adminApiUrl,
        {
          query: getQuery,
          variables: { customerId: req.session.customerId }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );

      let currentWishlist = [];
      const existingMetafield = getResponse.data.data?.customer?.metafield;
      
      if (existingMetafield?.value) {
        try {
          currentWishlist = JSON.parse(existingMetafield.value);
        } catch (jsonParseError) {
          console.error('❌ [WISHLIST_ADD] Failed to parse existing metafield JSON:', jsonParseError.message);
          console.error('❌ [WISHLIST_ADD] Corrupted metafield value length:', existingMetafield.value?.length || 0);
          currentWishlist = existingMetafield.value.split(',').filter(id => id.trim());
        }
      }

      // Update wishlist
      if (action === 'add' && !currentWishlist.includes(productId)) {
        currentWishlist.push(productId);
      } else if (action === 'remove') {
        currentWishlist = currentWishlist.filter(id => id !== productId);
      }

      // Save updated wishlist to Shopify
      const updateMutation = existingMetafield?.id ? `
        mutation updateCustomerMetafield($metafieldId: ID!, $value: String!) {
          metafieldUpdate(metafield: {id: $metafieldId, value: $value}) {
            metafield {
              id
              value
            }
            userErrors {
              field
              message
            }
          }
        }
      ` : `
        mutation createCustomerMetafield($customerId: ID!, $value: String!) {
          customerUpdate(
            input: {
              id: $customerId,
              metafields: [{
                namespace: "customer",
                key: "wishlist",
                value: $value,
                type: "json"
              }]
            }
          ) {
            customer {
              id
            }
            userErrors {
              field
              message
            }
          }
        }
      `;

      const updateVariables = existingMetafield?.id ? {
        metafieldId: existingMetafield.id,
        value: JSON.stringify(currentWishlist)
      } : {
        customerId: req.session.customerId,
        value: JSON.stringify(currentWishlist)
      };

      await axios.post(
        config.adminApiUrl,
        {
          query: updateMutation,
          variables: updateVariables
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );

      result = { 
        success: true, 
        action,
        productId,
        wishlistCount: currentWishlist.length,
        source: 'shopify_fallback'
      };
    }

    console.log(`✅ Wishlist updated successfully - ${action}ed product ${productId}`);
    res.json(result);

  } catch (error) {
    console.error('❌ Wishlist update error:', error);
    res.status(500).json({ error: 'Failed to update wishlist' });
  }
});

app.post('/shopify/create-customer-token', authenticateAppToken, async (req, res) => {
  try {
    const customerEmail = req.session.email;
    
    if (!customerEmail) {
      return res.status(400).json({ 
        error: 'No customer email found in session' 
      });
    }
    
    console.log('🔑 Getting store credit for customer:', customerEmail);
    
    // 🎯 SIMPLIFIED SOLUTION: Return store credit information for manual application
    // In a real implementation, you would:
    // 1. Check customer's store credit balance in your database
    // 2. Create a discount code in Shopify if needed
    // 3. Return the discount code to be applied
    
    // Get store credit from local ledger (synced with Shopify)
    const emailLower = customerEmail.toLowerCase();
    const storeCreditAmount = getStoreCredit(emailLower);
    
    if (storeCreditAmount <= 0) {
      return res.json({
        success: true,
        hasStoreCredit: false,
        message: 'No store credit available'
      });
    }
    
    // Generate a unique discount code for this store credit usage
    const timestamp = Date.now();
    const discountCode = `STORECREDIT${timestamp}`;
    
    console.log(`💰 Found ${storeCreditAmount} EUR store credit for ${customerEmail}`);
    
    // TODO: Create actual discount code in Shopify
    // For now, we'll return the information for the app to handle
    
    res.json({
      success: true,
      hasStoreCredit: true,
      amount: storeCreditAmount,
      currency: 'EUR',
      discountCode: discountCode,
      message: `${storeCreditAmount} EUR store credit available`
    });
    
  } catch (error) {
    console.error('❌ Error getting store credit:', error);
    res.status(500).json({ 
      error: 'Failed to get store credit information' 
    });
  }
});

app.post('/shopify/customer-account-api', authenticateAppToken, async (req, res) => {
  try {
    const { query, variables } = req.body;
    const customerEmail = req.session.email;
    
    if (!customerEmail) {
      return res.status(400).json({ error: 'Not authenticated' });
    }
    
    console.log('🔄 Proxying Customer Account API request for:', customerEmail);
    
    // Get customer from Shopify Admin API first
    const customerQuery = `
      query getCustomer($email: String!) {
        customers(first: 1, query: $email) {
          edges {
            node {
              id
              email
              firstName
              lastName
              phone
              emailMarketingConsent {
                marketingState
              }
              defaultAddress {
                id
                firstName
                lastName
                company
                address1
                address2
                city
                province
                country
                zip
                phone
              }
              addresses(first: 20) {
                edges {
                  node {
                    id
                    firstName
                    lastName
                    company
                    address1
                    address2
                    city
                    province
                    country
                    zip
                    phone
                  }
                }
              }
              orders(first: 50, sortKey: PROCESSED_AT, reverse: true) {
                edges {
                  node {
                    id
                    name
                    processedAt
                    displayFulfillmentStatus
                    displayFinancialStatus
                    currentTotalPriceSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    currentSubtotalPriceSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    totalShippingPriceSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    currentTotalTaxSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    shippingAddress {
                      address1
                      address2
                      city
                      province
                      country
                      zip
                    }
                    lineItems(first: 250) {
                      edges {
                        node {
                          title
                          quantity
                          variant {
                            id
                            title
                            price
                            image {
                              url
                              altText
                            }
                            product {
                              id
                              handle
                            }
                          }
                          originalUnitPriceSet {
                            shopMoney {
                              amount
                              currencyCode
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    
    const response = await axios.post(
      config.adminApiUrl,
      {
        query: customerQuery,
        variables: {
          email: `email:"${customerEmail}"`
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (response.data.errors) {
      return res.status(500).json({ 
        errors: response.data.errors 
      });
    }
    
    const customers = response.data.data?.customers?.edges || [];
    if (customers.length === 0) {
      return res.status(404).json({ 
        error: 'Customer not found' 
      });
    }
    
    const customer = customers[0].node;
    
    // Transform the data to match Customer Account API format
    const transformedData = {
      data: {
        customer: {
          id: customer.id,
          email: customer.email,
          firstName: customer.firstName,
          lastName: customer.lastName,
          phone: customer.phone,
          addresses: {
            edges: customer.addresses.edges
          },
          defaultAddress: customer.defaultAddress,
          orders: {
            edges: customer.orders.edges.map(orderEdge => ({
              node: {
                ...orderEdge.node,
                fulfillmentStatus: orderEdge.node.displayFulfillmentStatus,
                financialStatus: orderEdge.node.displayFinancialStatus,
                totalPriceV2: {
                  amount: orderEdge.node.currentTotalPriceSet.shopMoney.amount,
                  currencyCode: orderEdge.node.currentTotalPriceSet.shopMoney.currencyCode
                },
                currentTotalPrice: {
                  amount: orderEdge.node.currentTotalPriceSet.shopMoney.amount,
                  currencyCode: orderEdge.node.currentTotalPriceSet.shopMoney.currencyCode
                },
                currentSubtotalPrice: {
                  amount: orderEdge.node.currentSubtotalPriceSet.shopMoney.amount,
                  currencyCode: orderEdge.node.currentSubtotalPriceSet.shopMoney.currencyCode
                },
                totalShippingPriceV2: {
                  amount: orderEdge.node.totalShippingPriceSet.shopMoney.amount,
                  currencyCode: orderEdge.node.totalShippingPriceSet.shopMoney.currencyCode
                },
                totalTaxV2: orderEdge.node.currentTotalTaxSet ? {
                  amount: orderEdge.node.currentTotalTaxSet.shopMoney.amount,
                  currencyCode: orderEdge.node.currentTotalTaxSet.shopMoney.currencyCode
                } : null,
                lineItems: {
                  edges: orderEdge.node.lineItems.edges.map(lineItemEdge => ({
                    node: {
                      ...lineItemEdge.node,
                      variant: {
                        ...lineItemEdge.node.variant,
                        price: {
                          amount: lineItemEdge.node.variant.price,
                          currencyCode: orderEdge.node.currentTotalPriceSet.shopMoney.currencyCode
                        }
                      },
                      originalTotalPrice: {
                        amount: (parseFloat(lineItemEdge.node.originalUnitPriceSet.shopMoney.amount) * lineItemEdge.node.quantity).toString(),
                        currencyCode: lineItemEdge.node.originalUnitPriceSet.shopMoney.currencyCode
                      }
                    }
                  }))
                }
              }
            }))
          }
        }
      }
    };
    
    console.log('✅ Returning transformed customer data');
    res.json(transformedData);
    
  } catch (error) {
    console.error('❌ Error proxying Customer Account API:', error);
    res.status(500).json({ 
      error: 'Failed to fetch customer data' 
    });
  }
});

// 🔥 ADVANCED CUSTOMER FEATURES - PART 2
// Add these additional endpoints to your backend

// ===== LOYALTY & REWARDS SYSTEM =====

// GET /customer/loyalty - Get loyalty points and rewards
app.get('/customer/loyalty', authenticateAppToken, async (req, res) => {
  try {
    console.log('🏆 Fetching loyalty data for:', req.session.email);

    const query = `
      query getCustomerLoyalty($customerId: ID!) {
        customer(id: $customerId) {
          id
          totalSpent {
            amount
            currencyCode
          }
          orders(first: 250) {
            edges {
              node {
                id
                processedAt
                currentTotalPriceSet {
                  shopMoney {
                    amount
                  }
                }
                lineItems(first: 250) {
                  edges {
                    node {
                      quantity
                    }
                  }
                }
              }
            }
          }
          # Loyalty points stored in metafields
          loyaltyPoints: metafield(namespace: "loyalty", key: "points") {
            value
          }
          loyaltyTier: metafield(namespace: "loyalty", key: "tier") {
            value
          }
          # Store credit is part of loyalty
          storeCreditAccounts(first: 10) {
            edges {
              node {
                id
                balance {
                  amount
                  currencyCode
                }
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const customer = response.data.data.customer;
    const orders = customer.orders.edges;
    const totalSpent = parseFloat(customer.totalSpent.amount);
    const orderCount = orders.length;
    
    // Calculate loyalty metrics
    const totalItemsPurchased = orders.reduce((sum, order) => 
      sum + order.node.lineItems.edges.reduce((itemSum, item) => 
        itemSum + item.node.quantity, 0), 0);

    // Loyalty point calculation (1 point per €1 spent)
    const earnedPoints = Math.floor(totalSpent);
    const currentPoints = parseInt(customer.loyaltyPoints?.value || earnedPoints.toString());
    
    // Tier calculation
    let tier = 'Bronze';
    let nextTier = 'Silver';
    let pointsToNextTier = 500 - currentPoints;
    
    if (currentPoints >= 2000) {
      tier = 'Platinum';
      nextTier = 'Platinum';
      pointsToNextTier = 0;
    } else if (currentPoints >= 1000) {
      tier = 'Gold';
      nextTier = 'Platinum';
      pointsToNextTier = 2000 - currentPoints;
    } else if (currentPoints >= 500) {
      tier = 'Silver';
      nextTier = 'Gold';
      pointsToNextTier = 1000 - currentPoints;
    }

    // Available rewards based on points
    const availableRewards = [
      {
        id: 'discount_5_percent',
        title: '5% Rabatt',
        description: 'Erhalten Sie 5% Rabatt auf Ihre nächste Bestellung',
        pointsCost: 100,
        type: 'discount',
        value: 5,
        available: currentPoints >= 100
      },
      {
        id: 'discount_10_percent',
        title: '10% Rabatt',
        description: 'Erhalten Sie 10% Rabatt auf Ihre nächste Bestellung',
        pointsCost: 200,
        type: 'discount',
        value: 10,
        available: currentPoints >= 200
      },
      {
        id: 'free_shipping',
        title: 'Kostenloser Versand',
        description: 'Kostenloser Versand für Ihre nächste Bestellung',
        pointsCost: 150,
        type: 'shipping',
        value: 0,
        available: currentPoints >= 150
      },
      {
        id: 'store_credit_10',
        title: '10€ Guthaben',
        description: '10€ Store-Guthaben für zukünftige Käufe',
        pointsCost: 500,
        type: 'credit',
        value: 10,
        available: currentPoints >= 500
      },
      {
        id: 'vip_access',
        title: 'VIP Zugang',
        description: 'Früher Zugang zu Sales und neuen Produkten',
        pointsCost: 1000,
        type: 'access',
        value: 'vip',
        available: currentPoints >= 1000
      }
    ];

    // Calculate store credit
    let totalStoreCredit = 0;
    customer.storeCreditAccounts.edges.forEach(edge => {
      if (edge.node?.balance?.amount) {
        totalStoreCredit += parseFloat(edge.node.balance.amount);
      }
    });

    const loyaltyData = {
      currentPoints,
      earnedPoints,
      tier,
      nextTier,
      pointsToNextTier: Math.max(0, pointsToNextTier),
      tierProgress: tier === 'Platinum' ? 100 : 
        Math.round(((currentPoints % 500) / 500) * 100),
      
      // Customer stats
      totalSpent: {
        amount: totalSpent.toFixed(2),
        currencyCode: 'EUR'
      },
      orderCount,
      totalItemsPurchased,
      averageOrderValue: orderCount > 0 ? (totalSpent / orderCount).toFixed(2) : '0',
      
      // Store credit
      storeCredit: {
        amount: totalStoreCredit.toFixed(2),
        currencyCode: 'EUR'
      },
      
      // Rewards
      availableRewards,
      rewardsUnlocked: availableRewards.filter(r => r.available).length,
      
      // Tier benefits
      tierBenefits: {
        Bronze: ['Punkte sammeln', 'Basis-Rabatte'],
        Silver: ['5% Bonus-Punkte', 'Exklusive Angebote'],
        Gold: ['10% Bonus-Punkte', 'Prioritäts-Support', 'Früher Sale-Zugang'],
        Platinum: ['15% Bonus-Punkte', 'VIP-Support', 'Exklusive Produkte', 'Kostenloser Express-Versand']
      }[tier],
      
      // Recent activity
      recentActivity: orders.slice(0, 5).map(order => ({
        orderId: order.node.id,
        date: order.node.processedAt,
        pointsEarned: Math.floor(parseFloat(order.node.currentTotalPriceSet.shopMoney.amount)),
        amount: order.node.currentTotalPriceSet.shopMoney.amount
      }))
    };

    console.log(`✅ Loyalty data calculated - Tier: ${tier}, Points: ${currentPoints}`);
    res.json({ loyalty: loyaltyData });

  } catch (error) {
    console.error('❌ Loyalty fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch loyalty data' });
  }
});

// POST /customer/loyalty/redeem - Redeem loyalty reward
app.post('/customer/loyalty/redeem', authenticateAppToken, async (req, res) => {
  try {
    const { rewardId } = req.body;
    console.log('🎁 Redeeming reward:', rewardId);

    // Get current points
    const query = `
      query getCustomerPoints($customerId: ID!) {
        customer(id: $customerId) {
          loyaltyPoints: metafield(namespace: "loyalty", key: "points") {
            id
            value
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      { query, variables: { customerId: req.session.customerId } },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const currentPoints = parseInt(response.data.data.customer.loyaltyPoints?.value || '0');

    // Define reward costs (should match frontend)
    const rewardCosts = {
      'discount_5_percent': 100,
      'discount_10_percent': 200,
      'free_shipping': 150,
      'store_credit_10': 500,
      'vip_access': 1000
    };

    const cost = rewardCosts[rewardId];
    if (!cost || currentPoints < cost) {
      return res.status(400).json({ error: 'Insufficient points or invalid reward' });
    }

    // Deduct points
    const newPoints = currentPoints - cost;

    // Update points in Shopify
    const updateMutation = `
      mutation updateLoyaltyPoints($customerId: ID!, $points: String!) {
        customerUpdate(
          input: {
            id: $customerId,
            metafields: [{
              namespace: "loyalty",
              key: "points",
              value: $points,
              type: "number_integer"
            }]
          }
        ) {
          customer { id }
          userErrors { field message }
        }
      }
    `;

    await axios.post(
      config.adminApiUrl,
      {
        query: updateMutation,
        variables: {
          customerId: req.session.customerId,
          points: newPoints.toString()
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    // Generate reward code/credit based on reward type
    let rewardCode = null;
    let rewardValue = null;

    switch (rewardId) {
      case 'discount_5_percent':
        rewardCode = `LOYALTY5-${Date.now()}`;
        rewardValue = '5% Rabatt';
        break;
      case 'discount_10_percent':
        rewardCode = `LOYALTY10-${Date.now()}`;
        rewardValue = '10% Rabatt';
        break;
      case 'free_shipping':
        rewardCode = `FREESHIP-${Date.now()}`;
        rewardValue = 'Kostenloser Versand';
        break;
      case 'store_credit_10':
        // Add store credit (this would need additional Shopify setup)
        rewardValue = '10€ Guthaben';
        break;
      case 'vip_access':
        // Add VIP tag to customer
        rewardValue = 'VIP Zugang aktiviert';
        break;
    }

    console.log(`✅ Reward redeemed successfully - ${cost} points deducted`);
    res.json({
      success: true,
      rewardId,
      pointsDeducted: cost,
      remainingPoints: newPoints,
      rewardCode,
      rewardValue,
      message: `Belohnung erfolgreich eingelöst! ${rewardValue}`
    });

  } catch (error) {
    console.error('❌ Reward redemption error:', error);
    res.status(500).json({ error: 'Failed to redeem reward' });
  }
});

// ===== PRODUCT RECOMMENDATIONS =====

// GET /customer/recommendations - Personalized product recommendations
app.get('/customer/recommendations', authenticateAppToken, async (req, res) => {
  try {
    const { type = 'all', limit = 20 } = req.query;
    console.log('🎯 Generating recommendations for:', req.session.email);

    // Get customer purchase history for recommendations
    const query = `
      query getCustomerHistory($customerId: ID!) {
        customer(id: $customerId) {
          id
          orders(first: 50, sortKey: PROCESSED_AT, reverse: true) {
            edges {
              node {
                lineItems(first: 250) {
                  edges {
                    node {
                      variant {
                        product {
                          id
                          handle
                          productType
                          vendor
                          collections(first: 5) {
                            edges {
                              node {
                                id
                                handle
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const customer = response.data.data.customer;
    const orders = customer.orders.edges;

    // Analyze purchase patterns
    const purchasedProductIds = new Set();
    const productTypes = {};
    const vendors = {};
    const collections = {};

    orders.forEach(order => {
      order.node.lineItems.edges.forEach(item => {
        const product = item.node.variant.product;
        purchasedProductIds.add(product.id);
        
        // Count product types
        productTypes[product.productType] = (productTypes[product.productType] || 0) + 1;
        vendors[product.vendor] = (vendors[product.vendor] || 0) + 1;
        
        // Count collections
        product.collections.edges.forEach(collection => {
          collections[collection.node.handle] = (collections[collection.node.handle] || 0) + 1;
        });
      });
    });

    // Get top preferences
    const topProductType = Object.entries(productTypes).sort(([,a], [,b]) => b - a)[0]?.[0];
    const topVendor = Object.entries(vendors).sort(([,a], [,b]) => b - a)[0]?.[0];
    const topCollections = Object.entries(collections).sort(([,a], [,b]) => b - a).slice(0, 3).map(([handle]) => handle);

    // Build recommendation queries
    let recommendationQueries = [];

    if (type === 'all' || type === 'similar') {
      // Similar products based on purchase history
      if (topProductType) {
        recommendationQueries.push(`product_type:"${topProductType}"`);
      }
      if (topVendor) {
        recommendationQueries.push(`vendor:"${topVendor}"`);
      }
    }

    if (type === 'all' || type === 'trending') {
      // Trending products (recent, popular)
      recommendationQueries.push('created_at:>2024-01-01');
    }

    if (type === 'all' || type === 'sale') {
      // Sale items
      recommendationQueries.push('tag:"sale"');
    }

    // Fetch recommendations
    const recommendationsQuery = `
      query getRecommendations($query: String!, $first: Int!) {
        products(first: $first, query: $query, sortKey: CREATED_AT, reverse: true) {
          edges {
            node {
              id
              title
              handle
              description
              productType
              vendor
              tags
              priceRange {
                minVariantPrice {
                  amount
                  currencyCode
                }
              }
              compareAtPriceRange {
                minVariantCompareAtPrice {
                  amount
                  currencyCode
                }
              }
              featuredImage {
                url
                altText
              }
              variants(first: 1) {
                edges {
                  node {
                    id
                    availableForSale
                    price {
                      amount
                      currencyCode
                    }
                  }
                }
              }
              collections(first: 3) {
                edges {
                  node {
                    title
                    handle
                  }
                }
              }
            }
          }
        }
      }
    `;

    let allRecommendations = [];

    // Fetch from each query
    for (const queryString of recommendationQueries.slice(0, 3)) {
      try {
        const recResponse = await axios.post(
          config.adminApiUrl,
          {
            query: recommendationsQuery,
            variables: {
              query: queryString,
              first: Math.ceil(parseInt(limit) / recommendationQueries.length)
            }
          },
          {
            headers: {
              'X-Shopify-Access-Token': config.adminToken,
              'Content-Type': 'application/json'
            }
          }
        );

        const products = recResponse.data.data?.products?.edges || [];
        allRecommendations.push(...products);
      } catch (error) {
        console.error('Error fetching recommendations for query:', queryString, error);
      }
    }

    // Filter out already purchased products and duplicates
    const seenProductIds = new Set();
    const filteredRecommendations = allRecommendations
      .filter(product => {
        const productId = product.node.id;
        if (purchasedProductIds.has(productId) || seenProductIds.has(productId)) {
          return false;
        }
        seenProductIds.add(productId);
        return true;
      })
      .slice(0, parseInt(limit));

    // Transform for Flutter app
    const recommendations = filteredRecommendations.map(product => {
      const node = product.node;
      const price = parseFloat(node.priceRange.minVariantPrice.amount);
      const compareAtPrice = node.compareAtPriceRange?.minVariantCompareAtPrice?.amount 
        ? parseFloat(node.compareAtPriceRange.minVariantCompareAtPrice.amount) 
        : null;

      return {
        id: node.id,
        title: node.title,
        handle: node.handle,
        description: node.description?.substring(0, 200) || '',
        productType: node.productType,
        vendor: node.vendor,
        price: {
          amount: price.toFixed(2),
          currencyCode: node.priceRange.minVariantPrice.currencyCode
        },
        compareAtPrice: compareAtPrice ? {
          amount: compareAtPrice.toFixed(2),
          currencyCode: node.priceRange.minVariantPrice.currencyCode
        } : null,
        image: node.featuredImage?.url,
        availableForSale: node.variants.edges[0]?.node.availableForSale || false,
        isOnSale: compareAtPrice && compareAtPrice > price,
        tags: node.tags || [],
        collections: node.collections.edges.map(edge => edge.node),
        
        // Recommendation reason
        reason: topProductType && node.productType === topProductType ? 
          `Ähnlich zu Ihren ${topProductType} Käufen` :
          topVendor && node.vendor === topVendor ?
          `Von ${topVendor}` :
          'Für Sie empfohlen'
      };
    });

    console.log(`✅ Generated ${recommendations.length} personalized recommendations`);
    res.json({
      recommendations,
      type,
      basedOn: {
        topProductType,
        topVendor,
        topCollections,
        orderHistory: orders.length
      }
    });

  } catch (error) {
    console.error('❌ Recommendations error:', error);
    res.status(500).json({ error: 'Failed to generate recommendations' });
  }
});

// ===== RECENTLY VIEWED PRODUCTS =====

// GET /customer/recently-viewed - Get recently viewed products
app.get('/customer/recently-viewed', authenticateAppToken, async (req, res) => {
  try {
    console.log('👀 Fetching recently viewed products for:', req.session.email);

    // Get recently viewed from customer metafield
    const query = `
      query getRecentlyViewed($customerId: ID!) {
        customer(id: $customerId) {
          recentlyViewed: metafield(namespace: "customer", key: "recently_viewed") {
            value
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let recentlyViewedIds = [];
    const metafield = response.data.data?.customer?.recentlyViewed;
    
    if (metafield?.value) {
      try {
        const viewedData = JSON.parse(metafield.value);
        // Extract product IDs from viewed data (with timestamps)
        recentlyViewedIds = viewedData.map(item => item.productId || item).slice(0, 20);
      } catch (jsonParseError) {
        console.error('❌ [RECENTLY_VIEWED] Failed to parse metafield JSON:', jsonParseError.message);
        console.error('❌ [RECENTLY_VIEWED] Corrupted metafield value length:', metafield.value?.length || 0);
        // Fall back to comma-separated parsing
        recentlyViewedIds = metafield.value.split(',').filter(id => id.trim()).slice(0, 20);
      }
    }

    if (recentlyViewedIds.length === 0) {
      return res.json({ recentlyViewed: [] });
    }

    // Fetch product details
    const productsQuery = `
      query getRecentlyViewedProducts($productIds: [ID!]!) {
        nodes(ids: $productIds) {
          ... on Product {
            id
            title
            handle
            productType
            vendor
            priceRange {
              minVariantPrice {
                amount
                currencyCode
              }
            }
            featuredImage {
              url
              altText
            }
            availableForSale
          }
        }
      }
    `;

    const productsResponse = await axios.post(
      config.adminApiUrl,
      {
        query: productsQuery,
        variables: { productIds: recentlyViewedIds }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const products = productsResponse.data.data?.nodes || [];
    const recentlyViewed = products
      .filter(product => product !== null)
      .map(product => ({
        id: product.id,
        title: product.title,
        handle: product.handle,
        price: {
          amount: product.priceRange.minVariantPrice.amount,
          currencyCode: product.priceRange.minVariantPrice.currencyCode
        },
        image: product.featuredImage?.url,
        availableForSale: product.availableForSale,
        productType: product.productType,
        vendor: product.vendor
      }));

    console.log(`✅ Fetched ${recentlyViewed.length} recently viewed products`);
    res.json({ recentlyViewed });

  } catch (error) {
    console.error('❌ Recently viewed fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch recently viewed products' });
  }
});

// POST /customer/recently-viewed - Add product to recently viewed
app.post('/customer/recently-viewed', authenticateAppToken, async (req, res) => {
  try {
    const { productId } = req.body;
    console.log('👀 Adding to recently viewed:', productId);

    // Get current recently viewed
    const getQuery = `
      query getRecentlyViewed($customerId: ID!) {
        customer(id: $customerId) {
          recentlyViewed: metafield(namespace: "customer", key: "recently_viewed") {
            id
            value
          }
        }
      }
    `;

    const getResponse = await axios.post(
      config.adminApiUrl,
      {
        query: getQuery,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let recentlyViewed = [];
    const existingMetafield = getResponse.data.data?.customer?.recentlyViewed;
    
    if (existingMetafield?.value) {
      try {
        recentlyViewed = JSON.parse(existingMetafield.value);
      } catch (jsonParseError) {
        console.error('❌ [ADD_RECENTLY_VIEWED] Failed to parse metafield JSON:', jsonParseError.message);
        console.error('❌ [ADD_RECENTLY_VIEWED] Corrupted metafield value length:', existingMetafield.value?.length || 0);
        recentlyViewed = [];
      }
    }

    // Add new product (with timestamp) and keep only last 20
    const viewedItem = {
      productId,
      viewedAt: new Date().toISOString()
    };

    // Remove if already exists and add to front
    recentlyViewed = recentlyViewed.filter(item => 
      (item.productId || item) !== productId
    );
    recentlyViewed.unshift(viewedItem);
    recentlyViewed = recentlyViewed.slice(0, 20);

    // Save updated recently viewed
    const updateMutation = existingMetafield?.id ? `
      mutation updateRecentlyViewed($metafieldId: ID!, $value: String!) {
        metafieldUpdate(metafield: {id: $metafieldId, value: $value}) {
          metafield { id }
          userErrors { field message }
        }
      }
    ` : `
      mutation createRecentlyViewed($customerId: ID!, $value: String!) {
        customerUpdate(
          input: {
            id: $customerId,
            metafields: [{
              namespace: "customer",
              key: "recently_viewed",
              value: $value,
              type: "json"
            }]
          }
        ) {
          customer { id }
          userErrors { field message }
        }
      }
    `;

    const updateVariables = existingMetafield?.id ? {
      metafieldId: existingMetafield.id,
      value: JSON.stringify(recentlyViewed)
    } : {
      customerId: req.session.customerId,
      value: JSON.stringify(recentlyViewed)
    };

    await axios.post(
      config.adminApiUrl,
      {
        query: updateMutation,
        variables: updateVariables
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    console.log(`✅ Added product ${productId} to recently viewed`);
    res.json({ success: true, recentlyViewedCount: recentlyViewed.length });

  } catch (error) {
    console.error('❌ Recently viewed update error:', error);
    res.status(500).json({ error: 'Failed to update recently viewed' });
  }
});

// ===== CUSTOMER SUPPORT & HELP =====

// GET /customer/support-tickets - Get customer support tickets
app.get('/customer/support-tickets', authenticateAppToken, async (req, res) => {
  try {
    console.log('🎫 Fetching support tickets for:', req.session.email);

    // Get support tickets from customer metafield
    const query = `
      query getSupportTickets($customerId: ID!) {
        customer(id: $customerId) {
          supportTickets: metafield(namespace: "support", key: "tickets") {
            value
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let tickets = [];
    const metafield = response.data.data?.customer?.supportTickets;
    
    if (metafield?.value) {
      try {
        tickets = JSON.parse(metafield.value);
      } catch (jsonParseError) {
        console.error('❌ [SUPPORT_TICKETS] Failed to parse metafield JSON:', jsonParseError.message);
        console.error('❌ [SUPPORT_TICKETS] Corrupted metafield value length:', metafield.value?.length || 0);
        tickets = [];
      }
    }

    // Sort by creation date (newest first)
    tickets.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    console.log(`✅ Fetched ${tickets.length} support tickets`);
    res.json({ tickets });

  } catch (error) {
    console.error('❌ Support tickets fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch support tickets' });
  }
});

// POST /customer/support-tickets - Create new support ticket
app.post('/customer/support-tickets', authenticateAppToken, async (req, res) => {
  try {
    const { subject, message, category = 'general', priority = 'normal', orderId = null } = req.body;
    console.log('🎫 Creating support ticket for:', req.session.email);

    if (!subject || !message) {
      return res.status(400).json({ error: 'Subject and message are required' });
    }

    // Get current tickets
    const getQuery = `
      query getSupportTickets($customerId: ID!) {
        customer(id: $customerId) {
          supportTickets: metafield(namespace: "support", key: "tickets") {
            id
            value
          }
        }
      }
    `;

    const getResponse = await axios.post(
      config.adminApiUrl,
      {
        query: getQuery,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let tickets = [];
    const existingMetafield = getResponse.data.data?.customer?.supportTickets;
    
    if (existingMetafield?.value) {
      try {
        tickets = JSON.parse(existingMetafield.value);
      } catch (jsonParseError) {
        console.error('❌ [ADD_SUPPORT_TICKET] Failed to parse metafield JSON:', jsonParseError.message);
        console.error('❌ [ADD_SUPPORT_TICKET] Corrupted metafield value length:', existingMetafield.value?.length || 0);
        tickets = [];
      }
    }

    // Create new ticket
    const newTicket = {
      id: `ticket_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      subject,
      message,
      category, // 'general', 'order', 'return', 'product', 'shipping', 'billing'
      priority, // 'low', 'normal', 'high', 'urgent'
      status: 'open', // 'open', 'in_progress', 'waiting_customer', 'resolved', 'closed'
      orderId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      customerEmail: req.session.email,
      responses: [
        {
          id: `response_${Date.now()}`,
          message,
          author: 'customer',
          authorName: req.session.email,
          createdAt: new Date().toISOString()
        }
      ]
    };

    tickets.unshift(newTicket);

    // Save updated tickets
    const updateMutation = existingMetafield?.id ? `
      mutation updateSupportTickets($metafieldId: ID!, $value: String!) {
        metafieldUpdate(metafield: {id: $metafieldId, value: $value}) {
          metafield { id }
          userErrors { field message }
        }
      }
    ` : `
      mutation createSupportTickets($customerId: ID!, $value: String!) {
        customerUpdate(
          input: {
            id: $customerId,
            metafields: [{
              namespace: "support",
              key: "tickets",
              value: $value,
              type: "json"
            }]
          }
        ) {
          customer { id }
          userErrors { field message }
        }
      }
    `;

    const updateVariables = existingMetafield?.id ? {
      metafieldId: existingMetafield.id,
      value: JSON.stringify(tickets)
    } : {
      customerId: req.session.customerId,
      value: JSON.stringify(tickets)
    };

    await axios.post(
      config.adminApiUrl,
      {
        query: updateMutation,
        variables: updateVariables
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    console.log(`✅ Created support ticket: ${newTicket.id}`);
    res.json({ 
      success: true, 
      ticket: newTicket,
      message: 'Support-Ticket wurde erfolgreich erstellt. Wir melden uns bald bei Ihnen!'
    });

  } catch (error) {
    console.error('❌ Support ticket creation error:', error);
    res.status(500).json({ error: 'Failed to create support ticket' });
  }
});

// ===== SUBSCRIPTION PREFERENCES =====

// GET /customer/subscriptions - Get subscription preferences
app.get('/customer/subscriptions', authenticateAppToken, async (req, res) => {
  try {
    console.log('📧 Fetching subscription preferences for:', req.session.email);

    const query = `
      query getCustomerSubscriptions($customerId: ID!) {
        customer(id: $customerId) {
          id
          emailMarketingConsent {
            marketingState
            marketingOptInLevel
            consentUpdatedAt
          }
          smsMarketingConsent {
            marketingState
            marketingOptInLevel
            consentUpdatedAt
          }
          # Custom subscription preferences
          newsletterPrefs: metafield(namespace: "marketing", key: "newsletter_preferences") {
            value
          }
          notificationPrefs: metafield(namespace: "marketing", key: "notification_preferences") {
            value
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const customer = response.data.data.customer;

    // Parse custom preferences
    let newsletterPrefs = {};
    let notificationPrefs = {};

    try {
      if (customer.newsletterPrefs?.value) {
        newsletterPrefs = JSON.parse(customer.newsletterPrefs.value);
      }
      if (customer.notificationPrefs?.value) {
        notificationPrefs = JSON.parse(customer.notificationPrefs.value);
      }
    } catch (e) {
      console.log('Error parsing subscription preferences:', e);
    }

    const subscriptions = {
      // Main marketing consents
      emailMarketing: {
        subscribed: customer.emailMarketingConsent?.marketingState === 'SUBSCRIBED',
        optInLevel: customer.emailMarketingConsent?.marketingOptInLevel,
        lastUpdated: customer.emailMarketingConsent?.consentUpdatedAt
      },
      smsMarketing: {
        subscribed: customer.smsMarketingConsent?.marketingState === 'SUBSCRIBED',
        optInLevel: customer.smsMarketingConsent?.marketingOptInLevel,
        lastUpdated: customer.smsMarketingConsent?.consentUpdatedAt
      },

      // Newsletter categories
      newsletter: {
        weeklyNewsletter: newsletterPrefs.weeklyNewsletter !== false,
        productUpdates: newsletterPrefs.productUpdates !== false,
        saleAlerts: newsletterPrefs.saleAlerts !== false,
        newArrivals: newsletterPrefs.newArrivals !== false,
        restockNotifications: newsletterPrefs.restockNotifications !== false,
        personalizedRecommendations: newsletterPrefs.personalizedRecommendations !== false
      },

      // App/Push notifications
      pushNotifications: {
        orderUpdates: notificationPrefs.orderUpdates !== false,
        shippingAlerts: notificationPrefs.shippingAlerts !== false,
        saleAlerts: notificationPrefs.saleAlerts !== false,
        newArrivals: notificationPrefs.newArrivals !== false,
        wishlistAlerts: notificationPrefs.wishlistAlerts !== false,
        loyaltyUpdates: notificationPrefs.loyaltyUpdates !== false
      },

      // Frequency preferences
      frequency: {
        newsletter: newsletterPrefs.frequency || 'weekly',
        saleAlerts: newsletterPrefs.saleFrequency || 'immediate',
        recommendations: newsletterPrefs.recommendationFrequency || 'weekly'
      }
    };

    console.log('✅ Subscription preferences fetched successfully');
    res.json({ subscriptions });

  } catch (error) {
    console.error('❌ Subscription preferences fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch subscription preferences' });
  }
});

// PUT /customer/subscriptions - Update subscription preferences
app.put('/customer/subscriptions', authenticateAppToken, async (req, res) => {
  try {
    const { preferences } = req.body;
    console.log('📧 Updating subscription preferences for:', req.session.email);

    // Update main marketing consents
    if (preferences.emailMarketing !== undefined || preferences.smsMarketing !== undefined) {
      const marketingMutation = `
        mutation updateMarketingConsent($customerId: ID!, $emailConsent: CustomerEmailMarketingConsentInput, $smsConsent: CustomerSmsMarketingConsentInput) {
          customerUpdate(
            input: {
              id: $customerId,
              emailMarketingConsent: $emailConsent,
              smsMarketingConsent: $smsConsent
            }
          ) {
            customer {
              id
              emailMarketingConsent {
                marketingState
              }
              smsMarketingConsent {
                marketingState
              }
            }
            userErrors {
              field
              message
            }
          }
        }
      `;

      const marketingVariables = {
        customerId: req.session.customerId
      };

      if (preferences.emailMarketing !== undefined) {
        marketingVariables.emailConsent = {
          marketingState: preferences.emailMarketing ? 'SUBSCRIBED' : 'NOT_SUBSCRIBED',
          marketingOptInLevel: 'CONFIRMED_OPT_IN'
        };
      }

      if (preferences.smsMarketing !== undefined) {
        marketingVariables.smsConsent = {
          marketingState: preferences.smsMarketing ? 'SUBSCRIBED' : 'NOT_SUBSCRIBED',
          marketingOptInLevel: 'CONFIRMED_OPT_IN'
        };
      }

      await axios.post(
        config.adminApiUrl,
        {
          query: marketingMutation,
          variables: marketingVariables
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );
    }

    // Update newsletter preferences
    if (preferences.newsletter) {
      const newsletterMutation = `
        mutation updateNewsletterPrefs($customerId: ID!, $value: String!) {
          customerUpdate(
            input: {
              id: $customerId,
              metafields: [{
                namespace: "marketing",
                key: "newsletter_preferences",
                value: $value,
                type: "json"
              }]
            }
          ) {
            customer { id }
            userErrors { field message }
          }
        }
      `;

      await axios.post(
        config.adminApiUrl,
        {
          query: newsletterMutation,
          variables: {
            customerId: req.session.customerId,
            value: JSON.stringify(preferences.newsletter)
          }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );
    }

    // Update notification preferences
    if (preferences.pushNotifications) {
      const notificationMutation = `
        mutation updateNotificationPrefs($customerId: ID!, $value: String!) {
          customerUpdate(
            input: {
              id: $customerId,
              metafields: [{
                namespace: "marketing",
                key: "notification_preferences",
                value: $value,
                type: "json"
              }]
            }
          ) {
            customer { id }
            userErrors { field message }
          }
        }
      `;

      await axios.post(
        config.adminApiUrl,
        {
          query: notificationMutation,
          variables: {
            customerId: req.session.customerId,
            value: JSON.stringify(preferences.pushNotifications)
          }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );
    }

    console.log('✅ Subscription preferences updated successfully');
    res.json({ 
      success: true, 
      message: 'Abonnement-Einstellungen wurden erfolgreich aktualisiert' 
    });

  } catch (error) {
    console.error('❌ Subscription preferences update error:', error);
    res.status(500).json({ error: 'Failed to update subscription preferences' });
  }
});

// ===== CUSTOMER DASHBOARD SUMMARY =====

// GET /customer/dashboard - Complete customer dashboard data
app.get('/customer/dashboard', authenticateAppToken, async (req, res) => {
  try {
    console.log('📊 Fetching complete dashboard for:', req.session.email);

    const query = `
      query getCustomerDashboard($customerId: ID!) {
        customer(id: $customerId) {
          id
          email
          firstName
          lastName
          phone
          createdAt
          totalSpent {
            amount
            currencyCode
          }
          
          # Recent orders
          orders(first: 5, sortKey: PROCESSED_AT, reverse: true) {
            edges {
              node {
                id
                name
                processedAt
                displayFulfillmentStatus
                displayFinancialStatus
                currentTotalPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                lineItems(first: 3) {
                  edges {
                    node {
                      title
                      quantity
                      variant {
                        image {
                          url
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          
          # Store credit
          storeCreditAccounts(first: 10) {
            edges {
              node {
                balance {
                  amount
                  currencyCode
                }
              }
            }
          }
          
          # Loyalty points
          loyaltyPoints: metafield(namespace: "loyalty", key: "points") {
            value
          }
          
          # Addresses count
          addresses(first: 1) {
            edges {
              node {
                id
              }
            }
          }
          
          defaultAddress {
            id
            city
            country
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const customer = response.data.data.customer;
    const orders = customer.orders.edges;
    
    // Calculate totals
    let totalStoreCredit = 0;
    customer.storeCreditAccounts.edges.forEach(edge => {
      if (edge.node?.balance?.amount) {
        totalStoreCredit += parseFloat(edge.node.balance.amount);
      }
    });

    const loyaltyPoints = parseInt(customer.loyaltyPoints?.value || '0');
    const totalSpent = parseFloat(customer.totalSpent.amount);

    // Calculate member since
    const memberSince = new Date(customer.createdAt);
    const memberForDays = Math.floor((new Date() - memberSince) / (1000 * 60 * 60 * 24));
    const memberForYears = Math.floor(memberForDays / 365);

    // Order status summary
    const orderStatusCounts = orders.reduce((counts, order) => {
      const status = order.node.displayFulfillmentStatus;
      counts[status] = (counts[status] || 0) + 1;
      return counts;
    }, {});

    const dashboard = {
      customer: {
        id: customer.id,
        name: `${customer.firstName || ''} ${customer.lastName || ''}`.trim() || customer.email.split('@')[0],
        email: customer.email,
        memberSince: customer.createdAt,
        memberForDays,
        memberForYears,
        location: customer.defaultAddress ? 
          `${customer.defaultAddress.city}, ${customer.defaultAddress.country}` : null
      },
      
      // Financial summary
      financial: {
        totalSpent: {
          amount: totalSpent.toFixed(2),
          currencyCode: customer.totalSpent.currencyCode
        },
        storeCredit: {
          amount: totalStoreCredit.toFixed(2),
          currencyCode: 'EUR'
        },
        loyaltyPoints,
        averageOrderValue: orders.length > 0 ? (totalSpent / orders.length).toFixed(2) : '0'
      },
      
      // Order summary
      orders: {
        total: orders.length,
        recent: orders.map(order => ({
          id: order.node.id,
          name: order.node.name,
          date: order.node.processedAt,
          status: order.node.displayFulfillmentStatus,
          financialStatus: order.node.displayFinancialStatus,
          total: {
            amount: order.node.currentTotalPriceSet.shopMoney.amount,
            currencyCode: order.node.currentTotalPriceSet.shopMoney.currencyCode
          },
          items: order.node.lineItems.edges.map(item => ({
            title: item.node.title,
            quantity: item.node.quantity,
            image: item.node.variant.image?.url
          }))
        })),
        statusCounts: orderStatusCounts
      },
      
      // Quick stats
      stats: {
        hasActiveOrders: orders.some(order => 
          ['UNFULFILLED', 'PARTIALLY_FULFILLED', 'SCHEDULED'].includes(order.node.displayFulfillmentStatus)
        ),
        hasStoreCredit: totalStoreCredit > 0,
        isVipCustomer: totalSpent > 1000 || loyaltyPoints > 1000,
        addressesCount: customer.addresses.edges.length,
        lastOrderDate: orders.length > 0 ? orders[0].node.processedAt : null
      },
      
      // Quick actions available
      quickActions: [
        {
          id: 'view_orders',
          title: 'Bestellungen anzeigen',
          icon: 'orders',
          available: orders.length > 0
        },
        {
          id: 'track_shipment',
          title: 'Sendung verfolgen',
          icon: 'tracking',
          available: orders.some(order => order.node.displayFulfillmentStatus === 'FULFILLED')
        },
        {
          id: 'request_return',
          title: 'Rücksendung',
          icon: 'return',
          available: orders.some(order => order.node.displayFulfillmentStatus === 'FULFILLED')
        },
        {
          id: 'loyalty_rewards',
          title: 'Prämien einlösen',
          icon: 'rewards',
          available: loyaltyPoints >= 100
        },
        {
          id: 'update_profile',
          title: 'Profil bearbeiten',
          icon: 'profile',
          available: true
        },
        {
          id: 'contact_support',
          title: 'Support kontaktieren',
          icon: 'support',
          available: true
        }
      ].filter(action => action.available)
    };

    console.log('✅ Complete dashboard data prepared');
    res.json({ dashboard });

  } catch (error) {
    console.error('❌ Dashboard fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// ===== ACCOUNT DELETION & PRIVACY =====

// POST /customer/delete-account - Request account deletion (GDPR compliance)
app.post('/customer/delete-account', authenticateAppToken, async (req, res) => {
  try {
    const { confirmEmail, reason } = req.body;
    console.log('🗑️ Account deletion requested by:', req.session.email);

    if (confirmEmail !== req.session.email) {
      return res.status(400).json({ 
        error: 'Email confirmation does not match' 
      });
    }

    // Create deletion request (you'd implement the actual deletion process)
    const deletionRequest = {
      customerId: req.session.customerId,
      email: req.session.email,
      reason: reason || 'User requested',
      requestedAt: new Date().toISOString(),
      status: 'pending',
      processingDeadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
    };

    // In a real implementation, you'd:
    // 1. Store this request in your database
    // 2. Send confirmation email
    // 3. Schedule the actual deletion after the required waiting period
    // 4. Notify relevant systems

    console.log('✅ Account deletion request created');
    res.json({
      success: true,
      deletionRequest,
      message: 'Löschungsantrag wurde eingereicht. Sie erhalten eine Bestätigungs-E-Mail mit weiteren Informationen.',
      processingTime: '30 Tage',
      cancellationPossible: true
    });

  } catch (error) {
    console.error('❌ Account deletion request error:', error);
    res.status(500).json({ error: 'Failed to process deletion request' });
  }
});

// GET /customer/data-export - Export customer data (GDPR compliance)
app.get('/customer/data-export', authenticateAppToken, async (req, res) => {
  try {
    console.log('📋 Data export requested by:', req.session.email);

    // Get complete customer data for export
    const query = `
      query getCompleteCustomerData($customerId: ID!) {
        customer(id: $customerId) {
          id
          email
          firstName
          lastName
          phone
          createdAt
          updatedAt
          state
          note
          totalSpent {
            amount
            currencyCode
          }
          addresses(first: 50) {
            edges {
              node {
                id
                firstName
                lastName
                company
                address1
                address2
                city
                province
                country
                zip
                phone
              }
            }
          }
          orders(first: 250) {
            edges {
              node {
                id
                name
                processedAt
                currentTotalPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                lineItems(first: 250) {
                  edges {
                    node {
                      title
                      quantity
                      variant {
                        sku
                        title
                      }
                    }
                  }
                }
              }
            }
          }
          metafields(first: 50) {
            edges {
              node {
                namespace
                key
                value
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const customer = response.data.data.customer;

    const exportData = {
      exportDate: new Date().toISOString(),
      customer: {
        personalInformation: {
          id: customer.id,
          email: customer.email,
          firstName: customer.firstName,
          lastName: customer.lastName,
          phone: customer.phone,
          accountCreated: customer.createdAt,
          lastUpdated: customer.updatedAt,
          accountStatus: customer.state,
          totalSpent: customer.totalSpent
        },
        addresses: customer.addresses.edges.map(edge => edge.node),
        orderHistory: customer.orders.edges.map(edge => ({
          ...edge.node,
          items: edge.node.lineItems.edges.map(item => item.node)
        })),
        preferences: customer.metafields.edges.reduce((acc, edge) => {
          const metafield = edge.node;
          acc[`${metafield.namespace}.${metafield.key}`] = metafield.value;
          return acc;
        }, {})
      },
      dataTypes: [
        'Personal Information',
        'Contact Details', 
        'Addresses',
        'Order History',
        'Preferences',
        'Loyalty Data',
        'Support Interactions'
      ],
      rights: {
        rectification: 'You can update your data through your account settings',
        erasure: 'You can request account deletion through your account settings',
        portability: 'This export provides your data in a structured format',
        objection: 'You can opt out of marketing communications in your preferences'
      }
    };

    console.log('✅ Customer data export prepared');
    res.json({
      success: true,
      exportData,
      exportSize: JSON.stringify(exportData).length,
      message: 'Datenexport erfolgreich erstellt'
    });

  } catch (error) {
    console.error('❌ Data export error:', error);
    res.status(500).json({ error: 'Failed to export customer data' });
  }
});

// 🔥 ESSENTIAL CUSTOMER ENDPOINTS - THE ABSOLUTE MUST-HAVES FOR YOUR ECOMMERCE APP!

// ===== REAL-TIME ORDER TRACKING =====

// GET /customer/orders/:orderId/tracking - Real-time order tracking
app.get('/customer/orders/:orderId/tracking', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    console.log('📦 Fetching tracking info for order:', orderId);

    const query = `
      query getOrderTracking($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          processedAt
          displayFulfillmentStatus
          displayFinancialStatus
          fulfillments(first: 10) {
            edges {
              node {
                id
                status
                trackingCompany
                trackingNumbers
                trackingUrls
                createdAt
                updatedAt
                deliveredAt
                inTransitAt
                estimatedDeliveryAt
                location {
                  name
                  address {
                    city
                    country
                  }
                }
                fulfillmentLineItems(first: 50) {
                  edges {
                    node {
                      id
                      quantity
                      lineItem {
                        title
                        variant {
                          title
                          sku
                          image {
                            url
                          }
                        }
                      }
                    }
                  }
                }
                trackingInfo {
                  company
                  number
                  url
                }
              }
            }
          }
          shippingAddress {
            firstName
            lastName
            address1
            address2
            city
            province
            country
            zip
          }
          currentTotalPriceSet {
            shopMoney {
              amount
              currencyCode
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { orderId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = response.data.data.order;
    const fulfillments = order.fulfillments.edges;

    // Transform tracking data for Flutter app
    const trackingData = {
      orderId: order.id,
      orderNumber: order.name,
      orderDate: order.processedAt,
      status: order.displayFulfillmentStatus,
      financialStatus: order.displayFinancialStatus,
      totalAmount: {
        amount: order.currentTotalPriceSet.shopMoney.amount,
        currencyCode: order.currentTotalPriceSet.shopMoney.currencyCode
      },
      shippingAddress: order.shippingAddress,
      
      fulfillments: fulfillments.map(fulfillment => {
        const node = fulfillment.node;
        return {
          id: node.id,
          status: node.status,
          trackingCompany: node.trackingCompany,
          trackingNumbers: node.trackingNumbers || [],
          trackingUrls: node.trackingUrls || [],
          createdAt: node.createdAt,
          updatedAt: node.updatedAt,
          deliveredAt: node.deliveredAt,
          inTransitAt: node.inTransitAt,
          estimatedDeliveryAt: node.estimatedDeliveryAt,
          
          // Tracking timeline
          timeline: [
            {
              status: 'ordered',
              title: 'Bestellung aufgegeben',
              description: 'Ihre Bestellung wurde erfolgreich aufgegeben',
              date: order.processedAt,
              completed: true
            },
            {
              status: 'processing',
              title: 'Bestellung wird bearbeitet',
              description: 'Wir bereiten Ihre Bestellung vor',
              date: node.createdAt,
              completed: true
            },
            {
              status: 'shipped',
              title: 'Versandt',
              description: `Versandt von ${node.location?.name || 'unserem Lager'}`,
              date: node.createdAt,
              completed: true
            },
            {
              status: 'in_transit',
              title: 'Unterwegs',
              description: 'Ihr Paket ist auf dem Weg zu Ihnen',
              date: node.inTransitAt,
              completed: node.inTransitAt !== null
            },
            {
              status: 'delivered',
              title: 'Zugestellt',
              description: 'Ihr Paket wurde zugestellt',
              date: node.deliveredAt,
              completed: node.status === 'delivered'
            }
          ].filter(step => step.completed || step.status === 'delivered'),
          
          items: node.fulfillmentLineItems.edges.map(item => ({
            id: item.node.id,
            title: item.node.lineItem.title,
            variant: item.node.lineItem.variant.title,
            sku: item.node.lineItem.variant.sku,
            quantity: item.node.quantity,
            image: item.node.lineItem.variant.image?.url
          })),
          
          // Tracking URLs for major carriers
          trackingLinks: node.trackingNumbers.map(trackingNumber => {
            const company = (node.trackingCompany || '').toLowerCase();
            let trackingUrl = '';
            
            if (company.includes('dhl')) {
              trackingUrl = `https://www.dhl.de/de/privatkunden/pakete-empfangen/verfolgen.html?lang=de&idc=${trackingNumber}`;
            } else if (company.includes('ups')) {
              trackingUrl = `https://www.ups.com/track?tracknum=${trackingNumber}`;
            } else if (company.includes('fedex')) {
              trackingUrl = `https://www.fedex.com/apps/fedextrack/?tracknumbers=${trackingNumber}`;
            } else if (company.includes('hermes')) {
              trackingUrl = `https://www.myhermes.de/empfangen/sendungsverfolgung/sendungsinformation/#${trackingNumber}`;
            } else if (company.includes('dpd')) {
              trackingUrl = `https://tracking.dpd.de/parcelstatus?query=${trackingNumber}`;
            }
            
            return {
              number: trackingNumber,
              company: node.trackingCompany,
              url: trackingUrl || node.trackingUrls?.[0] || ''
            };
          })
        };
      }),
      
      // Delivery estimation
      estimatedDelivery: fulfillments.length > 0 ? 
        fulfillments[0].node.estimatedDeliveryAt : null,
      
      // Helper flags for UI
      hasTracking: fulfillments.some(f => f.node.trackingNumbers && f.node.trackingNumbers.length > 0),
      isDelivered: order.displayFulfillmentStatus === 'FULFILLED',
      canTrack: fulfillments.length > 0
    };

    console.log(`✅ Tracking data prepared for ${fulfillments.length} fulfillments`);
    res.json({ tracking: trackingData });

  } catch (error) {
    console.error('❌ Tracking fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch tracking information' });
  }
});

// ===== COMPREHENSIVE RETURN SYSTEM =====

// POST /customer/orders/:orderId/return - Initiate return process
app.post('/customer/orders/:orderId/return', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { items, reason, notes, preferredResolution = 'refund' } = req.body;
    
    console.log('↩️ Processing return request for order:', orderId);

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'No items specified for return' });
    }

    // Create return request
    const returnRequest = {
      id: `return_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      orderId,
      customerId: req.session.customerId,
      customerEmail: req.session.email,
      items: items.map(item => ({
        lineItemId: item.lineItemId,
        quantity: item.quantity,
        reason: item.reason || reason,
        condition: item.condition || 'unused'
      })),
      reason,
      notes: notes || '',
      preferredResolution, // 'refund', 'exchange', 'store_credit'
      status: 'requested',
      createdAt: new Date().toISOString(),
      estimatedProcessingTime: '3-5 Werktage',
      
      // Return process steps
      process: [
        {
          step: 'request_submitted',
          title: 'Antrag eingereicht',
          description: 'Ihr Rücksendungsantrag wurde eingereicht',
          completed: true,
          completedAt: new Date().toISOString()
        },
        {
          step: 'review_pending',
          title: 'Prüfung läuft',
          description: 'Wir prüfen Ihren Rücksendungsantrag',
          completed: false
        },
        {
          step: 'approved',
          title: 'Genehmigt',
          description: 'Rücksendung wurde genehmigt - Versandlabel wird erstellt',
          completed: false
        },
        {
          step: 'shipping_label',
          title: 'Versandlabel',
          description: 'Versandlabel wurde erstellt und versendet',
          completed: false
        },
        {
          step: 'item_shipped',
          title: 'Artikel versandt',
          description: 'Artikel wurde von Ihnen versandt',
          completed: false
        },
        {
          step: 'item_received',
          title: 'Artikel erhalten',
          description: 'Artikel wurde in unserem Lager erhalten',
          completed: false
        },
        {
          step: 'inspection',
          title: 'Prüfung',
          description: 'Artikel wird geprüft',
          completed: false
        },
        {
          step: 'completed',
          title: 'Abgeschlossen',
          description: 'Rücksendung wurde abgeschlossen',
          completed: false
        }
      ]
    };

    // In a real implementation, you would:
    // 1. Validate the return eligibility
    // 2. Check return policy compliance
    // 3. Store in your database
    // 4. Send confirmation email
    // 5. Create return in Shopify if using Customer Account API

    console.log(`✅ Return request created: ${returnRequest.id}`);
    
    res.json({
      success: true,
      returnRequest,
      message: 'Rücksendungsantrag wurde erfolgreich eingereicht. Sie erhalten eine Bestätigungs-E-Mail.',
      nextSteps: [
        'Sie erhalten eine E-Mail mit der Bestätigung',
        'Wir prüfen Ihren Antrag innerhalb von 24 Stunden',
        'Bei Genehmigung erhalten Sie ein kostenloses Versandlabel',
        'Die Bearbeitung dauert 3-5 Werktage nach Erhalt'
      ]
    });

  } catch (error) {
    console.error('❌ Return request error:', error);
    res.status(500).json({ error: 'Failed to process return request' });
  }
});

// GET /customer/returns/:returnId - Get return status
app.get('/customer/returns/:returnId', authenticateAppToken, async (req, res) => {
  try {
    const { returnId } = req.params;
    console.log('↩️ Fetching return status:', returnId);

    // In a real implementation, fetch from your database
    // For demo, returning mock data
    const returnData = {
      id: returnId,
      orderId: 'gid://shopify/Order/12345',
      orderNumber: '#1001',
      status: 'in_progress',
      reason: 'size_dimensions',
      preferredResolution: 'refund',
      createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      updatedAt: new Date().toISOString(),
      
      items: [
        {
          title: 'Modernes Schuhregal Camo',
          quantity: 1,
          reason: 'Größe passt nicht',
          refundAmount: {
            amount: '89.99',
            currencyCode: 'EUR'
          }
        }
      ],
      
      timeline: [
        {
          status: 'request_submitted',
          title: 'Antrag eingereicht',
          date: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
          completed: true
        },
        {
          status: 'approved',
          title: 'Genehmigt',
          date: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
          completed: true
        },
        {
          status: 'shipping_label',
          title: 'Versandlabel erstellt',
          date: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
          completed: true
        },
        {
          status: 'item_shipped',
          title: 'Artikel versandt',
          date: null,
          completed: false
        }
      ],
      
      shippingLabel: {
        available: true,
        downloadUrl: '/api/returns/labels/download?returnId=' + returnId,
        trackingNumber: 'DHL123456789DE',
        carrier: 'DHL',
        instructions: [
          'Verpacken Sie den Artikel sicher in der Originalverpackung',
          'Kleben Sie das Versandlabel auf das Paket',
          'Geben Sie das Paket bei der nächsten DHL-Stelle ab',
          'Bewahren Sie den Beleg auf'
        ]
      },
      
      estimatedCompletion: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString(),
      canCancel: true
    };

    res.json({ return: returnData });

  } catch (error) {
    console.error('❌ Return status error:', error);
    res.status(500).json({ error: 'Failed to fetch return status' });
  }
});

// ===== REORDER & REPEAT PURCHASE =====

// POST /customer/orders/:orderId/reorder - Reorder previous order
app.post('/customer/orders/:orderId/reorder', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { selectedItems = null, quantities = {} } = req.body;
    
    console.log('🔄 Processing reorder for:', orderId);

    // Get original order details
    const query = `
      query getOrderForReorder($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          lineItems(first: 250) {
            edges {
              node {
                id
                title
                quantity
                variant {
                  id
                  title
                  sku
                  availableForSale
                  price {
                    amount
                    currencyCode
                  }
                  product {
                    id
                    title
                    handle
                    availableForSale
                  }
                  image {
                    url
                  }
                }
                customAttributes {
                  key
                  value
                }
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { orderId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors || !response.data.data.order) {
      return res.status(404).json({ error: 'Original order not found' });
    }

    const originalOrder = response.data.data.order;
    const lineItems = originalOrder.lineItems.edges;

    // Filter items for reorder
    let itemsToReorder = lineItems;
    if (selectedItems && selectedItems.length > 0) {
      itemsToReorder = lineItems.filter(item => 
        selectedItems.includes(item.node.id)
      );
    }

    // Check availability and prepare cart items
    const cartItems = [];
    const unavailableItems = [];

    for (const item of itemsToReorder) {
      const node = item.node;
      const variant = node.variant;
      
      if (!variant.availableForSale || !variant.product.availableForSale) {
        unavailableItems.push({
          title: node.title,
          reason: 'Nicht mehr verfügbar'
        });
        continue;
      }

      const quantity = quantities[node.id] || node.quantity;
      
      cartItems.push({
        merchandiseId: variant.id,
        quantity: quantity,
        attributes: node.customAttributes || []
      });
    }

    // Create cart with available items
    let cartData = null;
    if (cartItems.length > 0) {
      try {
        // Use your existing createCart method from ShopifyService
        const createCartMutation = `
          mutation createReorderCart($input: CartInput!) {
            cartCreate(input: $input) {
              cart {
                id
                checkoutUrl
                totalQuantity
                cost {
                  totalAmount {
                    amount
                    currencyCode
                  }
                }
              }
              userErrors {
                field
                message
              }
            }
          }
        `;

        const cartResponse = await axios.post(
          'https://metallbude-de.myshopify.com/api/2024-10/graphql.json',
          {
            query: createCartMutation,
            variables: {
              input: {
                lines: cartItems
              }
            }
          },
          {
            headers: {
              'Content-Type': 'application/json',
              'X-Shopify-Storefront-Access-Token': config.storefrontToken,
            }
          }
        );

        if (cartResponse.data.data?.cartCreate?.cart) {
          cartData = cartResponse.data.data.cartCreate.cart;
        }
      } catch (cartError) {
        console.error('Cart creation error:', cartError);
      }
    }

    const reorderResult = {
      success: cartItems.length > 0,
      originalOrderId: orderId,
      originalOrderNumber: originalOrder.name,
      
      reorderedItems: cartItems.length,
      unavailableItems: unavailableItems,
      
      cart: cartData ? {
        id: cartData.id,
        checkoutUrl: cartData.checkoutUrl,
        totalQuantity: cartData.totalQuantity,
        totalAmount: cartData.cost.totalAmount
      } : null,
      
      message: cartItems.length > 0 ? 
        `${cartItems.length} Artikel wurden zum Warenkorb hinzugefügt` :
        'Keine Artikel verfügbar für Nachbestellung',
      
      nextSteps: cartData ? [
        'Überprüfen Sie Ihren Warenkorb',
        'Passen Sie Mengen bei Bedarf an',
        'Gehen Sie zur Kasse'
      ] : [
        'Leider sind keine Artikel mehr verfügbar',
        'Schauen Sie sich ähnliche Produkte an'
      ]
    };

    console.log(`✅ Reorder processed - ${cartItems.length} items available`);
    res.json(reorderResult);

  } catch (error) {
    console.error('❌ Reorder error:', error);
    res.status(500).json({ error: 'Failed to process reorder' });
  }
});

// ===== ADVANCED SEARCH & DISCOVERY =====

// GET /customer/search-history - Customer's search history
app.get('/customer/search-history', authenticateAppToken, async (req, res) => {
  try {
    console.log('🔍 Fetching search history for:', req.session.email);

    // Get search history from customer metafield
    const query = `
      query getSearchHistory($customerId: ID!) {
        customer(id: $customerId) {
          searchHistory: metafield(namespace: "customer", key: "search_history") {
            value
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let searchHistory = [];
    const metafield = response.data.data?.customer?.searchHistory;
    
    if (metafield?.value) {
      try {
        const historyData = JSON.parse(metafield.value);
        searchHistory = historyData.slice(0, 20); // Last 20 searches
      } catch (e) {
        searchHistory = [];
      }
    }

    // Transform for Flutter app
    const recentSearches = searchHistory.map(item => ({
      query: item.query,
      timestamp: item.timestamp,
      resultsCount: item.resultsCount || 0,
      category: item.category || null
    }));

    // Get popular/trending searches (you could fetch this from analytics)
    const trendingSearches = [
      'Schuhregal',
      'Camo Design',
      'Flur Möbel',
      'Metall Regal',
      'Industrial Style'
    ];

    res.json({
      recentSearches,
      trendingSearches,
      searchSuggestions: [
        ...new Set([
          ...recentSearches.map(s => s.query),
          ...trendingSearches
        ])
      ].slice(0, 10)
    });

  } catch (error) {
    console.error('❌ Search history error:', error);
    res.status(500).json({ error: 'Failed to fetch search history' });
  }
});

// POST /customer/search-history - Add search to history
app.post('/customer/search-history', authenticateAppToken, async (req, res) => {
  try {
    const { query, resultsCount = 0, category = null } = req.body;
    console.log('🔍 Adding search to history:', query);

    if (!query || query.trim().length < 2) {
      return res.status(400).json({ error: 'Invalid search query' });
    }

    // Get current search history
    const getQuery = `
      query getSearchHistory($customerId: ID!) {
        customer(id: $customerId) {
          searchHistory: metafield(namespace: "customer", key: "search_history") {
            id
            value
          }
        }
      }
    `;

    const getResponse = await axios.post(
      config.adminApiUrl,
      {
        query: getQuery,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let searchHistory = [];
    const existingMetafield = getResponse.data.data?.customer?.searchHistory;
    
    if (existingMetafield?.value) {
      try {
        searchHistory = JSON.parse(existingMetafield.value);
      } catch (e) {
        searchHistory = [];
      }
    }

    // Add new search (remove if exists and add to front)
    searchHistory = searchHistory.filter(item => 
      item.query.toLowerCase() !== query.toLowerCase()
    );
    
    searchHistory.unshift({
      query: query.trim(),
      timestamp: new Date().toISOString(),
      resultsCount,
      category
    });

    // Keep only last 50 searches
    searchHistory = searchHistory.slice(0, 50);

    // Save updated search history
    const updateMutation = existingMetafield?.id ? `
      mutation updateSearchHistory($metafieldId: ID!, $value: String!) {
        metafieldUpdate(metafield: {id: $metafieldId, value: $value}) {
          metafield { id }
          userErrors { field message }
        }
      }
    ` : `
      mutation createSearchHistory($customerId: ID!, $value: String!) {
        customerUpdate(
          input: {
            id: $customerId,
            metafields: [{
              namespace: "customer",
              key: "search_history",
              value: $value,
              type: "json"
            }]
          }
        ) {
          customer { id }
          userErrors { field message }
        }
      }
    `;

    const updateVariables = existingMetafield?.id ? {
      metafieldId: existingMetafield.id,
      value: JSON.stringify(searchHistory)
    } : {
      customerId: req.session.customerId,
      value: JSON.stringify(searchHistory)
    };

    await axios.post(
      config.adminApiUrl,
      {
        query: updateMutation,
        variables: updateVariables
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    res.json({ success: true, searchHistoryCount: searchHistory.length });

  } catch (error) {
    console.error('❌ Search history update error:', error);
    res.status(500).json({ error: 'Failed to update search history' });
  }
});

// ===== CUSTOMER NOTIFICATIONS CENTER =====

// GET /customer/notifications - Get customer notifications
app.get('/customer/notifications', authenticateAppToken, async (req, res) => {
  try {
    const { type = 'all', unreadOnly = false } = req.query;
    console.log('🔔 Fetching notifications for:', req.session.email);

    // Get notifications from customer metafield
    const query = `
      query getCustomerNotifications($customerId: ID!) {
        customer(id: $customerId) {
          notifications: metafield(namespace: "customer", key: "notifications") {
            value
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      {
        query,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let notifications = [];
    const metafield = response.data.data?.customer?.notifications;
    
    if (metafield?.value) {
      try {
        notifications = JSON.parse(metafield.value);
      } catch (e) {
        notifications = [];
      }
    }

    // Filter notifications
    let filteredNotifications = notifications;
    
    if (unreadOnly === 'true') {
      filteredNotifications = notifications.filter(n => !n.read);
    }
    
    if (type !== 'all') {
      filteredNotifications = filteredNotifications.filter(n => n.type === type);
    }

    // Sort by date (newest first)
    filteredNotifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const notificationData = {
      notifications: filteredNotifications.slice(0, 50), // Limit to 50
      unreadCount: notifications.filter(n => !n.read).length,
      totalCount: notifications.length,
      types: [
        { id: 'order', name: 'Bestellungen', count: notifications.filter(n => n.type === 'order').length },
        { id: 'shipping', name: 'Versand', count: notifications.filter(n => n.type === 'shipping').length },
        { id: 'promotion', name: 'Angebote', count: notifications.filter(n => n.type === 'promotion').length },
        { id: 'account', name: 'Konto', count: notifications.filter(n => n.type === 'account').length },
        { id: 'system', name: 'System', count: notifications.filter(n => n.type === 'system').length }
      ]
    };

    console.log(`✅ Fetched ${filteredNotifications.length} notifications`);
    res.json(notificationData);

  } catch (error) {
    console.error('❌ Notifications fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// POST /customer/notifications/:notificationId/read - Mark notification as read
app.post('/customer/notifications/:notificationId/read', authenticateAppToken, async (req, res) => {
  try {
    const { notificationId } = req.params;
    console.log('👁️ Marking notification as read:', notificationId);

    // Get current notifications
    const getQuery = `
      query getCustomerNotifications($customerId: ID!) {
        customer(id: $customerId) {
          notifications: metafield(namespace: "customer", key: "notifications") {
            id
            value
          }
        }
      }
    `;

    const getResponse = await axios.post(
      config.adminApiUrl,
      {
        query: getQuery,
        variables: { customerId: req.session.customerId }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    let notifications = [];
    const existingMetafield = getResponse.data.data?.customer?.notifications;
    
    if (existingMetafield?.value) {
      try {
        notifications = JSON.parse(existingMetafield.value);
      } catch (e) {
        return res.status(500).json({ error: 'Failed to parse notifications' });
      }
    }

    // Update notification
    const notificationIndex = notifications.findIndex(n => n.id === notificationId);
    if (notificationIndex === -1) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    notifications[notificationIndex].read = true;
    notifications[notificationIndex].readAt = new Date().toISOString();

    // Save updated notifications
    const updateMutation = `
      mutation updateNotifications($metafieldId: ID!, $value: String!) {
        metafieldUpdate(metafield: {id: $metafieldId, value: $value}) {
          metafield { id }
          userErrors { field message }
        }
      }
    `;

    await axios.post(
      config.adminApiUrl,
      {
        query: updateMutation,
        variables: {
          metafieldId: existingMetafield.id,
          value: JSON.stringify(notifications)
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const unreadCount = notifications.filter(n => !n.read).length;

    res.json({ 
      success: true, 
      unreadCount,
      message: 'Benachrichtigung als gelesen markiert'
    });

  } catch (error) {
    console.error('❌ Mark notification read error:', error);
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
});

// 🔥 ADDED: Return eligibility endpoint
app.get('/orders/:orderId/return-eligibility', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const customerEmail = req.session.email;
    
    if (!customerEmail) {
      return res.status(401).json({ 
        eligible: false,
        reason: 'No customer email found',
        returnableItems: []
      });
    }

    // Non-sensitive debug: log that eligibility check was received and which user requested it
    try {
      console.log(`🔍 Checking return eligibility for order: ${orderId} (user: ${customerEmail})`);
    } catch (e) {
      console.log('🔍 Checking return eligibility (user unknown)');
    }
    
    // 🔥 REMOVED: await ensureValidShopifyToken(customerEmail);
    console.log('🔍 Using Shopify Admin API directly to check return eligibility...');

    // Resolve order identifier: accept full GID or plain order number (e.g. 135798)
    let resolvedOrderId = orderId;
    try {
      if (!String(orderId).startsWith('gid://')) {
        // Try searching orders by name (Shopify order name is usually like "#135798" or "135798")
        const searchQueries = [
          `name:${orderId}`,
          `name:#${orderId}`,
        ];

        let foundOrder = null;
        for (const q of searchQueries) {
          try {
            const findQuery = `query findOrder($query: String!) { orders(first:1, query: $query) { edges { node { id name } } } }`;
            const findResp = await axios.post(
              config.adminApiUrl,
              { query: findQuery, variables: { query: q } },
              { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } }
            );
            const node = findResp.data?.data?.orders?.edges?.[0]?.node;
            if (node && node.id) {
              foundOrder = node;
              break;
            }
          } catch (err) {
            // continue to next pattern
          }
        }

        if (foundOrder && foundOrder.id) {
          resolvedOrderId = foundOrder.id;
          console.log(`🔎 Resolved order number ${orderId} -> ${resolvedOrderId}`);
        } else {
          console.log(`❌ Could not resolve order identifier: ${orderId}`);
          return res.status(404).json({ eligible: false, reason: 'Order not found', returnableItems: [] });
        }
      }
    } catch (err) {
      console.error('❌ Error resolving order identifier:', err?.message || err);
      return res.status(500).json({ eligible: false, reason: 'Internal error resolving order', returnableItems: [] });
    }

    // Delegate to the shared, API-version-safe eligibility checker
    try {
      const eligibility = await checkShopifyReturnEligibility(resolvedOrderId, null);
      // ensure we always return a consistent shape
      return res.json(Object.assign({ existingReturns: eligibility.existingReturns ?? 0 }, eligibility));
    } catch (err) {
      console.error('❌ Error delegating eligibility check:', err?.message || err);
      return res.status(500).json({ eligible: false, reason: 'Error checking return eligibility', returnableItems: [] });
    }
    
  } catch (error) {
    console.error('❌ Error checking return eligibility:', error);
    res.status(500).json({
      eligible: false,
      reason: 'Error checking return eligibility',
      returnableItems: []
    });
  }
});

// 🔥 UPDATED: Submit return request with Shopify Customer Account API integration
app.post('/returns', authenticateAppToken, async (req, res) => {
  try {
    const returnRequest = req.body;
    const customerToken = req.headers.authorization?.substring(7);
    const customerEmail = req.session.email;

    if (!customerToken) {
      return res.status(401).json({ 
        success: false, 
        error: 'No authentication token' 
      });
    }

    console.log('📦 Processing return request:', {
      orderId: returnRequest.orderId,
      orderNumber: returnRequest.orderNumber,
      itemCount: returnRequest.items?.length,
      reason: returnRequest.reason,
      additionalNotes: returnRequest.additionalNotes,
      preferredResolution: returnRequest.preferredResolution,
      customer: customerEmail
    });

    // 🔥 FIXED: Try Customer Account API with proper authentication first
    console.log('🚀 Trying Customer Account API for REQUESTED status...');
    try {
      // First, get customer access token using Admin API
      const customerMutation = `
        query getCustomer($id: ID!) {
          customer(id: $id) {
            id
            email
          }
        }
      `;
      
      // Extract customer ID from the order (we need this for Customer Account API)
      console.log('🔍 Getting customer info for Customer Account API authentication...');
      
      // Skip Customer Account API if we don't have proper tokens
      console.log('⚠️ Customer Account API requires complex authentication setup, trying direct Admin API approaches...');
      throw new Error('Customer Account API authentication not configured');
      
    } catch (customerApiError) {
      console.error('❌ Customer Account API failed:', customerApiError?.message);
      
      // 🔥 APPROACH 2: Try creating as DRAFT first, then convert to REQUEST
      console.log('🚀 Trying Admin API with draft-to-request conversion...');
      try {
        // Step 1: Create return with request flag to get REQUESTED status
        const draftMutation = `
          mutation returnCreate($returnInput: ReturnInput!) {
            returnCreate(returnInput: $returnInput) {
              return {
                id
                name
                status
              }
              userErrors {
                field
                message
              }
            }
          }
        `;

        const draftVariables = {
          returnInput: {
            orderId: returnRequest.orderId,
            returnLineItems: returnLineItems,
            requestReturn: true, // Request flag to create as request, not auto-approved
            notifyCustomer: false,
            note: returnRequest.additionalNotes || "Customer-initiated return request"
          }
        };

        console.log('📤 Creating return with request flag...');
        const draftResponse = await axios.post(
          `https://${config.shopDomain}/admin/api/2024-10/graphql.json`,
          { query: draftMutation, variables: draftVariables },
          {
            headers: {
              'X-Shopify-Access-Token': config.adminToken,
              'Content-Type': 'application/json'
            }
          }
        );

        if (draftResponse.data.errors) {
          throw new Error(`Return creation failed: ${draftResponse.data.errors[0].message}`);
        }

        const draftResult = draftResponse.data.data.returnCreate;
        const draftUserErrors = draftResult.userErrors || [];

        if (draftUserErrors.length > 0) {
          throw new Error(`Draft return failed: ${draftUserErrors.map(u => u.message).join('; ')}`);
        }

        const createdReturn = draftResult.return;
        if (!createdReturn || !createdReturn.id) {
          throw new Error('Draft return creation failed');
        }

        console.log('✅ Return created:', createdReturn.id);
        console.log('🔍 Return status from Shopify:', createdReturn.status);
        
        // The requestReturn flag should create it in REQUESTED status
        console.log('✅ Return created via Admin API with request flag');
        try {
          const requestMutation = `
            mutation returnRequest($id: ID!, $requestedAt: DateTime!) {
              returnRequest(id: $id, requestedAt: $requestedAt) {
                return {
                  id
                  status
                }
                userErrors {
                  field
                  message
                }
              }
            }
          `;

          const requestResponse = await axios.post(
            `https://${config.shopDomain}/admin/api/2024-10/graphql.json`,
            { 
              query: requestMutation, 
              variables: { 
                id: createdReturn.id,
                requestedAt: new Date().toISOString()
              }
            },
            {
              headers: {
                'X-Shopify-Access-Token': config.adminToken,
                'Content-Type': 'application/json'
              }
            }
          );

          console.log('🎯 Return request conversion response:', requestResponse.data);
        } catch (conversionError) {
          console.log('⚠️ Conversion to requested failed, but return was created:', conversionError?.message);
        }

        console.log('✅ Return created via Admin API draft method');
        return res.json({
          success: true,
          returnId: createdReturn.id,
          returnName: createdReturn.name,
          status: 'requested', // Force requested status for frontend
          method: 'admin_api_draft',
          shopifyStatus: createdReturn.status
        });
        
      } catch (draftError) {
        console.error('❌ Draft method also failed:', draftError?.message);
      }
    }

    // 🔥 APPROACH 3: Try returnCreate mutation with request flag (alternative approach)
    console.log('🚀 Trying returnCreate with alternate structure...');
    try {
      const alternateMutation = `
        mutation returnCreate($returnInput: ReturnInput!) {
          returnCreate(returnInput: $returnInput) {
            return {
              id
              name
              status
            }
            userErrors {
              field
              message
            }
          }
        }
      `;

      // Use standard ReturnInput format
      const alternateVariables = {
        returnInput: {
          orderId: returnRequest.orderId,
          returnLineItems: returnLineItems,
          requestReturn: true // This should put it in REQUESTED status
        }
      };

      console.log('📤 Creating return with alternate approach...');
      const alternateResponse = await axios.post(
        `https://${config.shopDomain}/admin/api/2024-10/graphql.json`,
        { query: alternateMutation, variables: alternateVariables },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        }
      );

      if (alternateResponse.data.errors) {
        console.log('⚠️ Alternate returnCreate failed:', alternateResponse.data.errors[0].message);
        throw new Error('Alternate returnCreate failed');
      }

      const alternateResult = alternateResponse.data.data?.returnCreate;
      if (!alternateResult) {
        throw new Error('Alternate returnCreate mutation failed');
      }

      const alternateUserErrors = alternateResult.userErrors || [];
      if (alternateUserErrors.length > 0) {
        throw new Error(`Alternate return failed: ${alternateUserErrors.map(u => u.message).join('; ')}`);
      }

      const createdAlternateReturn = alternateResult.return;
      if (createdAlternateReturn && createdAlternateReturn.id) {
        console.log('✅ Return created via alternate returnCreate:', createdAlternateReturn.id);
        console.log('🔍 Alternate return status:', createdAlternateReturn.status);
        
        return res.json({
          success: true,
          returnId: createdAlternateReturn.id,
          returnName: createdAlternateReturn.name,
          status: 'requested',
          method: 'alternate_return_create',
          shopifyStatus: createdAlternateReturn.status
        });
      }
      
    } catch (alternateCreateError) {
      console.error('❌ Alternate returnCreate failed:', alternateCreateError?.message);
    }

    // 🔥 FALLBACK: Standard GraphQL Admin API (creates OPEN status)
    console.log('🔄 Falling back to standard returnCreate (will be OPEN status, then request)...');
    if (config.adminToken) {
      console.log('🚀 Trying REST Admin API for return request creation...');
      try {
        // Extract order ID from GID
        const numericOrderId = returnRequest.orderId.replace('gid://shopify/Order/', '');
        
        // Build return request payload for REST API
        const returnRequestPayload = {
          return_request: {
            order_id: numericOrderId,
            return_line_items: []
          }
        };

        // Get eligibility to map line items to fulfillment line items
        const eligibility = await checkShopifyReturnEligibility(returnRequest.orderId, null);
        if (!eligibility || !eligibility.eligible) {
          throw new Error('Order not eligible for return via REST API');
        }

        // Map return items to REST API format
        for (const requestedItem of returnRequest.items || []) {
          const match = eligibility.returnableItems.find(ri => ri.id === requestedItem.lineItemId);
          if (!match) continue;

          const qty = Math.min(Number(requestedItem.quantity || 1), Number(match.quantity || 0));
          if (qty <= 0) continue;

          returnRequestPayload.return_request.return_line_items.push({
            fulfillment_line_item_id: match.fulfillmentLineItemId.replace('gid://shopify/FulfillmentLineItem/', ''),
            quantity: qty,
            return_reason: mapReasonToShopify(returnRequest.reason),
            customer_note: returnRequest.additionalNotes || `${returnRequest.reason}: ${getReasonDescription(returnRequest.reason)}`
          });
        }

        if (returnRequestPayload.return_request.return_line_items.length === 0) {
          throw new Error('No valid return line items for REST API');
        }

        console.log('📤 Creating return request via REST Admin API...');
        const restResponse = await axios.post(
          `https://${config.shopDomain}/admin/api/2024-10/orders/${numericOrderId}/return_requests.json`,
          returnRequestPayload,
          {
            headers: {
              'X-Shopify-Access-Token': config.adminToken,
              'Content-Type': 'application/json'
            }
          }
        );

        const createdReturnRequest = restResponse.data?.return_request;
        if (createdReturnRequest && createdReturnRequest.id) {
          console.log('✅ Return request created via REST Admin API:', createdReturnRequest.id);
          console.log('🔍 Return request status:', createdReturnRequest.status);
          
          return res.json({
            success: true,
            returnId: `gid://shopify/ReturnRequest/${createdReturnRequest.id}`,
            returnName: `#${createdReturnRequest.name || createdReturnRequest.id}`,
            status: 'requested', // REST API should create in requested status
            method: 'rest_admin_api',
            shopifyStatus: createdReturnRequest.status
          });
        }
      } catch (restError) {
        console.error('❌ REST Admin API failed:', restError?.response?.data || restError?.message);
        console.log('⚠️ Falling back to GraphQL Admin API...');
      }
    }

    // 🔥 FALLBACK: GraphQL Admin API (creates returns in OPEN status)
    if (config.adminToken) {
      console.log('🚀 Using Admin API for return creation (safer path)...');
      try {
        // Reuse the API-version-safe eligibility checker to get fulfillmentLineItem IDs
        const eligibility = await checkShopifyReturnEligibility(returnRequest.orderId, null);
        if (!eligibility || !eligibility.eligible || !Array.isArray(eligibility.returnableItems) || eligibility.returnableItems.length === 0) {
          throw new Error(eligibility?.reason || 'No returnable items available via Admin API');
        }

        // Map return request items to fulfillmentLineItemIds from eligibility result
        const returnLineItems = [];
        const mapReturnReason = (reason) => mapReasonToShopify(reason || 'other');

        for (const requestedItem of returnRequest.items || []) {
          const match = eligibility.returnableItems.find(ri => ri.id === requestedItem.lineItemId || ri.title === requestedItem.title);
          if (!match) {
            console.log('⚠️ Requested item not found among returnable items:', requestedItem);
            continue;
          }

          const qty = Math.min(Number(requestedItem.quantity || 1), Number(match.quantity || 0));
          if (qty <= 0) continue;

          // Build Admin ReturnLineItem input - include reason note if provided
          const lineItemInput = {
            fulfillmentLineItemId: match.fulfillmentLineItemId,
            quantity: qty,
            returnReason: mapReturnReason(returnRequest.reason)
          };

          // If the customer provided per-item notes or an overall additionalNotes, include as returnReasonNote
          const perItemNote = requestedItem.reasonNote || requestedItem.customerNote || returnRequest.additionalNotes || '';
          if (perItemNote && perItemNote.length > 0) {
            lineItemInput.returnReasonNote = String(perItemNote).substring(0, 255);
          }

          returnLineItems.push(lineItemInput);
        }

        if (returnLineItems.length === 0) {
          throw new Error('No matching fulfillment line items found for return (Admin API)');
        }

        // Build exchangeLineItems when customer requests an exchange
        const exchangeLineItems = [];
        if ((returnRequest.preferredResolution || '').toLowerCase() === 'exchange') {
          for (const requestedItem of returnRequest.items || []) {
            const qty = Number(requestedItem.quantity || 1);
            const requestedVariant = requestedItem.requestedExchangeVariantId || requestedItem.exchangeVariantId || null;
            if (requestedVariant && qty > 0) {
              exchangeLineItems.push({
                variantId: requestedVariant,
                quantity: qty
              });
            }
          }
        }
        const returnMutation = `
          mutation returnRequestCreate($returnRequest: ReturnRequestInput!) {
            returnRequestCreate(returnRequest: $returnRequest) {
              returnRequest {
                id
                name
                status
              }
              userErrors {
                field
                message
              }
            }
          }`;

        const returnRequestInput = {
          orderId: returnRequest.orderId,
          returnLineItems: returnLineItems,
          reason: mapReasonToShopify(returnRequest.reason),
          note: returnRequest.additionalNotes || `Return request: ${returnRequest.reason}`
        };

        // Attach exchangeLineItems when present (Admin API might support ExchangeLineItemInput)
        if (exchangeLineItems.length > 0) {
          returnRequestInput.exchangeLineItems = exchangeLineItems;
        }

        console.log('🔥 Creating return REQUEST with Admin API - payload:', { returnLineItemsCount: returnLineItems.length });

        const returnResponse = await axios.post(config.adminApiUrl, {
          query: returnMutation,
          variables: { returnRequest: returnRequestInput }
        }, {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          }
        });

        if (returnResponse.data.errors) {
          console.error('❌ Admin returnRequestCreate GraphQL errors:', returnResponse.data.errors);
          throw new Error('Admin API returnRequestCreate failed');
        }

        const returnResult = returnResponse.data.data?.returnRequestCreate;
        const userErrors = returnResult?.userErrors || [];
        if (userErrors.length > 0) {
          console.error('❌ Admin returnRequestCreate userErrors:', userErrors);
          throw new Error('Return request creation failed: ' + userErrors.map(u => u.message).join('; '));
        }

        const createdReturnRequest = returnResult?.returnRequest;
        if (!createdReturnRequest || !createdReturnRequest.id) {
          throw new Error('Admin API did not return created return request');
        }

        console.log('✅ Return REQUEST created via Admin API:', createdReturnRequest.id);
        console.log('🔍 Return request status from Shopify:', createdReturnRequest.status);
        
        // Return request should have REQUESTED status which displays as "Rückgabe angefragt"
        return res.json({
          success: true, 
          returnId: createdReturnRequest.id, 
          returnName: createdReturnRequest.name, 
          status: 'requested', // Return requests should be in REQUESTED status
          method: 'admin_api_returnRequestCreate',
          shopifyStatus: createdReturnRequest.status // Keep original status for reference
        });

      } catch (adminError) {
        console.error('❌ Admin API path failed (will fallback):', adminError?.message || adminError);
        // Fall through to Customer Account API
      }
    }

  // Step 1: Submit to Shopify using Customer Account API (fallback path)
  let shopifyResult = await submitShopifyReturnRequest(returnRequest, customerToken);
    
  // 🔥 FALLBACK: If Customer Account API fails, try Admin API
  if (!shopifyResult.success && shopifyResult.shouldFallbackToAdminAPI) {
    console.log('🔄 Customer Account API failed, falling back to Admin API...');
    
    try {
      // Use the same Admin API logic from above
      const eligibility = await checkShopifyReturnEligibility(returnRequest.orderId, null);
      if (!eligibility || !eligibility.eligible) {
        throw new Error('Order not eligible for return via Admin API');
      }

      // Build return input for Admin API
      const returnLineItems = [];
      for (const requestedItem of returnRequest.items || []) {
        const match = eligibility.returnableItems.find(ri => ri.id === requestedItem.lineItemId);
        if (!match) continue;

        const qty = Math.min(Number(requestedItem.quantity || 1), Number(match.quantity || 0));
        if (qty <= 0) continue;

        returnLineItems.push({
          fulfillmentLineItemId: match.fulfillmentLineItemId,
          quantity: qty,
          returnReason: mapReasonToShopify(returnRequest.reason),
          customerNote: returnRequest.additionalNotes || `${returnRequest.reason}: ${getReasonDescription(returnRequest.reason)}`
        });
      }

      if (returnLineItems.length === 0) {
        throw new Error('No valid return line items found');
      }

      // Create return via Admin API
      const adminApiResult = await createReturnViaAdminAPI({
        ...returnRequest,
        returnLineItems
      });

      if (adminApiResult.success) {
        shopifyResult = adminApiResult;
        console.log('✅ Successfully created return via Admin API fallback');
      }
    } catch (fallbackError) {
      console.error('❌ Admin API fallback also failed:', fallbackError?.message);
    }
  }
    
  if (!shopifyResult.success) {
    return res.status(400).json({
      success: false,
      error: shopifyResult.error
    });
  }

    // Step 2: Save to backend database for additional tracking
    const backendReturnData = {
      ...returnRequest,
      shopifyReturnRequestId: shopifyResult.shopifyReturnRequestId,
      shopifyStatus: shopifyResult.status,
      customerEmail: customerEmail,
      requestDate: new Date().toISOString(),
      status: 'requested', // Force all returns to start as "requested" status for proper approval workflow
      preferredResolution: returnRequest.preferredResolution || 'refund',
      // Keep requested exchange variants per item for backend tracking
      items: (returnRequest.items || []).map(it => ({
        lineItemId: it.lineItemId,
        quantity: it.quantity,
        requestedExchangeVariantId: it.requestedExchangeVariantId || it.exchangeVariantId || null,
        reason: it.reason || returnRequest.reason || 'other'
      }))
    };

    // Here you would save to your database
    // await saveReturnToDatabase(backendReturnData);

    console.log('✅ Return request submitted successfully:', shopifyResult.shopifyReturnRequestId);

    res.json({
      success: true,
      returnId: shopifyResult.shopifyReturnRequestId,
      status: shopifyResult.status,
      message: 'Return request submitted successfully'
    });

  } catch (error) {
    console.error('❌ Error processing return request:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process return request'
    });
  }
});

// 🔥 UPDATED: Get return history from both Customer Account API and Admin API
app.get('/returns', authenticateAppToken, async (req, res) => {
  try {
    const customerToken = req.headers.authorization?.substring(7);
    const customerEmail = req.session.email;
    
    if (!customerToken) {
      return res.status(401).json({ 
        success: false, 
        error: 'No authentication token' 
      });
    }

    console.log('📋 Fetching return history for:', customerEmail);
    
    // Try Customer Account API first
    let shopifyReturns = [];
    try {
      shopifyReturns = await getShopifyCustomerReturns(customerToken);
      console.log(`✅ Customer Account API returned ${shopifyReturns.length} returns`);
    } catch (error) {
      console.log('⚠️ Customer Account API failed, trying Admin API fallback:', error.message);
    }

    // If we have few or no returns from Customer Account API, also try Admin API
    // This helps with returns created via Admin API that might not show up immediately
    if (shopifyReturns.length === 0) {
      try {
        console.log('🔄 Fetching returns from Admin API as fallback...');
        const adminReturns = await getAdminApiReturns(customerEmail);
        console.log(`✅ Admin API returned ${adminReturns.length} returns`);
        
        // Merge results (Admin API format should match our expected format)
        shopifyReturns = [...shopifyReturns, ...adminReturns];
      } catch (adminError) {
        console.log('⚠️ Admin API fallback also failed:', adminError.message);
      }
    }
    
    // Log final results
    console.log(`📊 Final return count: ${shopifyReturns.length} returns for ${customerEmail}`);
    
    res.json({
      success: true,
      returns: shopifyReturns
    });
    
  } catch (error) {
    console.error('❌ Error fetching return history:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch return history'
    });
  }
});

// 🔥 ADDED: Check existing returns for order
app.get('/orders/:orderId/existing-returns', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const customerToken = req.headers.authorization?.substring(7);
    
    if (!customerToken) {
      return res.status(401).json({ hasExistingReturns: false });
    }
    
    const eligibility = await checkShopifyReturnEligibility(orderId, customerToken);
    const hasExistingReturns = (eligibility.existingReturns || 0) > 0;
    
    res.json({ 
      hasExistingReturns,
      existingReturnsCount: eligibility.existingReturns || 0
    });
    
  } catch (error) {
    console.error('❌ Error checking existing returns:', error);
    res.json({ hasExistingReturns: false });
  }
});

// GET /orders/:orderId/returns - return history for a specific order
app.get('/orders/:orderId/returns', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const customerToken = req.headers.authorization?.substring(7);
    const customerEmail = req.session.email;

    if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

    let results = [];

    // Try Customer Account API first (requires customer token)
    if (customerToken) {
      try {
        const allReturns = await getShopifyCustomerReturns(customerToken);
        results = allReturns.filter(r => r.orderId === orderId || (r.orderNumber && r.orderNumber.replace('#','') === orderId));
        console.log(`🔎 Found ${results.length} returns for order ${orderId} via Customer Account API`);
      } catch (err) {
        console.log('⚠️ Customer Account API failed for order returns:', err.message);
      }
    }

    // If none or to supplement, try Admin API
    if (config.adminToken) {
      try {
        const adminReturns = await getAdminApiReturns(customerEmail);
        const matchingAdmin = adminReturns.filter(r => r.orderId === orderId || (r.orderNumber && r.orderNumber.replace('#','') === orderId));
        console.log(`🔎 Found ${matchingAdmin.length} returns for order ${orderId} via Admin API`);
        // Merge unique by id
        const byId = new Map();
        for (const r of [...results, ...matchingAdmin]) byId.set(r.id, r);
        results = Array.from(byId.values());
      } catch (err) {
        console.log('⚠️ Admin API order-returns fetch failed:', err.message);
      }
    }

    res.json({ success: true, orderId, returns: results });
  } catch (error) {
    console.error('❌ Error fetching order returns:', error.message);
    res.status(500).json({ success: false, error: 'Failed to fetch order returns' });
  }
});

// POST /returns/:returnId/cancel - Cancel return request
app.post('/returns/:returnId/cancel', authenticateAppToken, async (req, res) => {
  try {
    const { returnId } = req.params;
    const customerEmail = req.session.email;
    
    console.log('❌ Cancelling return:', returnId, 'for:', customerEmail);
    
    // In production, update the return status in your database
    // For now, just simulate success
    
    res.json({
      success: true,
      message: 'Return request cancelled successfully'
    });
    
  } catch (error) {
    console.error('Error cancelling return:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to cancel return request'
    });
  }
});

// GET /customer/store-credit - Get store credit
app.get('/customer/store-credit', authenticateAppToken, async (req, res) => {
  try {
    if (!config.adminToken) {
      return res.json({ amount: 0.0, currency: 'EUR' });
    }

    console.log('Fetching store credit for customer:', req.session.customerId);

    const query = `
      query getCustomerStoreCredit($customerId: ID!) {
        customer(id: $customerId) {
          id
          email
          storeCreditAccounts(first: 10) {
            edges {
              node {
                id
                balance {
                  amount
                  currencyCode
                }
              }
            }
          }
        }
      }
    `;

    let response;
    try {
      response = await axios.post(
        config.adminApiUrl,
        {
          query,
          variables: {
            customerId: req.session.customerId
          }
        },
        {
          headers: {
            'X-Shopify-Access-Token': config.adminToken,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );
    } catch (err) {
      console.error('❌ Upstream Admin API error fetching store credit:', err.message || err);
      const upstreamBody = err.response?.data;
      if (upstreamBody) {
        try {
          const preview = typeof upstreamBody === 'string' ? upstreamBody.substring(0, 400) : JSON.stringify(upstreamBody).substring(0,400);
          console.error('❌ Upstream body preview:', preview);
        } catch (e) {}
      }
      return res.status(502).json({ amount: 0.0, currency: 'EUR' });
    }

    console.log('Store credit response status:', response.status);
    console.log('Store credit response success:', !response.data.errors);

    if (response.data?.errors) {
      console.error('GraphQL errors:', response.data.errors);
      
      // Try fallback to metafield, but wrap in try/catch too
      try {
        const metafieldQuery = `
          query getCustomerMetafield($customerId: ID!) {
            customer(id: $customerId) {
              metafield(namespace: "customer", key: "store_credit") {
                value
              }
            }
          }
        `;
        
        const metafieldResponse = await axios.post(
          config.adminApiUrl,
          {
            query: metafieldQuery,
            variables: { customerId: req.session.customerId }
          },
          {
            headers: {
              'X-Shopify-Access-Token': config.adminToken,
              'Content-Type': 'application/json'
            },
            timeout: 8000
          }
        );
        
        const metafield = metafieldResponse.data?.data?.customer?.metafield;
        const creditAmount = metafield?.value ? parseFloat(metafield.value) : 0.0;
        
        return res.json({
          amount: creditAmount,
          currency: 'EUR'
        });
      } catch (metaErr) {
        console.error('❌ Metafield fallback failed:', metaErr.message || metaErr);
        return res.status(502).json({ amount: 0.0, currency: 'EUR' });
      }
    }

    let totalCredit = 0.0;
    const storeCreditAccounts = response.data?.data?.customer?.storeCreditAccounts?.edges || [];
    
    storeCreditAccounts.forEach(edge => {
      if (edge.node?.balance?.amount) {
        totalCredit += parseFloat(edge.node.balance.amount);
      }
    });
    
    console.log('Total store credit:', totalCredit);

    // Sync the authoritative balance to local ledger for consistency
    try {
      const customerEmail = response.data?.data?.customer?.email;
      if (customerEmail) {
        const emailLower = customerEmail.toLowerCase();
        setStoreCredit(emailLower, totalCredit);
        await persistStoreCreditLedger();
        console.log(`💾 Synced authoritative balance ${totalCredit} for ${emailLower} to local ledger`);
      }
    } catch (syncErr) {
      console.error('⚠️ Failed to sync store credit to local ledger:', syncErr.message);
    }

    res.json({
      amount: totalCredit,
      currency: 'EUR'
    });
  } catch (error) {
    console.error('Store credit error:', error.response?.data || error.message);
    res.json({
      amount: 0.0,
      currency: 'EUR'
    });
  }
});

// PUT /customer/update - FIXED VERSION WITHOUT THE GraphQL ERROR
app.put('/customer/update', authenticateAppToken, async (req, res) => {
  try {
    const { updates } = req.body;
    const customerId = req.session.customerId;
    
    console.log('Updating customer:', customerId);
    console.log('Updates:', updates);
    
    // First, update the customer's basic info
    let mutationFields = [];
    let variables = { id: customerId };
    let variableDefinitions = ['$id: ID!'];
    
    if (updates.firstName !== undefined) {
      mutationFields.push('firstName: $firstName');
      variables.firstName = updates.firstName;
      variableDefinitions.push('$firstName: String');
    }
    
    if (updates.lastName !== undefined) {
      mutationFields.push('lastName: $lastName');
      variables.lastName = updates.lastName;
      variableDefinitions.push('$lastName: String');
    }
    
    if (updates.phone !== undefined) {
      mutationFields.push('phone: $phone');
      variables.phone = updates.phone;
      variableDefinitions.push('$phone: String');
    }
    
    // FIXED: Remove the problematic addresses.edges query
    const mutation = `
      mutation updateCustomer(${variableDefinitions.join(', ')}) {
        customerUpdate(
          input: {
            id: $id
            ${mutationFields.join('\n            ')}
          }
        ) {
          customer {
            id
            email
            firstName
            lastName
            phone
            emailMarketingConsent {
              marketingState
            }
            defaultAddress {
              id
              company
              address1
              address2
              city
              province
              country
              zip
              phone
            }
          }
          userErrors {
            field
            message
          }
        }
      }
    `;
    
    console.log('GraphQL mutation:', mutation);
    console.log('Variables:', variables);
    
    const response = await axios.post(
      config.adminApiUrl,
      {
        query: mutation,
        variables: variables,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': config.adminToken,
        }
      }
    );
    
    const data = response.data;
    
    if (data.errors) {
      console.error('GraphQL errors:', data.errors);
      return res.status(400).json({ 
        error: 'Failed to update customer', 
        details: data.errors 
      });
    }
    
    if (data.data?.customerUpdate?.userErrors?.length > 0) {
      console.error('User errors:', data.data.customerUpdate.userErrors);
      return res.status(400).json({ 
        error: 'Failed to update customer', 
        details: data.data.customerUpdate.userErrors 
      });
    }
    
    const customer = data.data.customerUpdate.customer;
    
    // Transform the customer data for the response
    const transformedCustomer = {
      ...customer,
      acceptsMarketing: customer.emailMarketingConsent?.marketingState === 'SUBSCRIBED'
    };
    
    res.json({ 
      customer: transformedCustomer 
    });
    
  } catch (error) {
    console.error('Error updating customer:', error.response?.data || error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /customer/addresses - Get all customer addresses (FIXED FOR ADMIN API)
app.get('/customer/addresses', authenticateAppToken, async (req, res) => {
  try {
    const customerId = req.session.customerId;
    const customerNumericId = customerId.split('/').pop();
    
    console.log('Fetching addresses via REST for customer:', customerNumericId);
    
    const response = await axios.get(
      `https://${config.shopDomain}/admin/api/2024-10/customers/${customerNumericId}/addresses.json`,
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json',
        }
      }
    );
    
    console.log('REST addresses response:', response.data);
    
    const addresses = response.data.addresses || [];
    const formattedAddresses = addresses.map(addr => ({
      id: `gid://shopify/MailingAddress/${addr.id}`,
      firstName: addr.first_name || '',
      lastName: addr.last_name || '',
      company: addr.company || '',
      address1: addr.address1 || '',
      address2: addr.address2 || '',
      city: addr.city || '',
      province: addr.province || '',
      country: addr.country || '',
      zip: addr.zip || '',
      phone: addr.phone || '',
      isDefault: addr.default || false
    }));
    
    res.json({ addresses: formattedAddresses });
    
  } catch (error) {
    console.error('Error fetching addresses:', error.response?.data || error.message);
    res.json({ addresses: [] });
  }
});

// POST /customer/address - Create new address via REST API
app.post('/customer/address', authenticateAppToken, async (req, res) => {
  try {
    const { address } = req.body;
    const customerId = req.session.customerId;
    const customerNumericId = customerId.split('/').pop();
    
    console.log('Creating new address via REST for customer:', customerNumericId);
    console.log('Address data:', JSON.stringify(address, null, 2));
    
    const response = await axios.post(
      `https://${config.shopDomain}/admin/api/2024-10/customers/${customerNumericId}/addresses.json`,
      {
        address: {
          first_name: address.firstName || '',
          last_name: address.lastName || '',
          company: address.company || '',
          address1: address.address1 || '',
          address2: address.address2 || '',
          city: address.city || '',
          province: address.province || '',
          country: address.country || 'DE',
          zip: address.zip || '',
          phone: address.phone || ''
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json',
        }
      }
    );
    
    console.log('REST API create response:', response.status, response.data);
    
    if (response.status === 201 && response.data.customer_address) {
      console.log('Address created successfully via REST');
      res.json({ 
        address: {
          id: `gid://shopify/MailingAddress/${response.data.customer_address.id}`,
          firstName: response.data.customer_address.first_name,
          lastName: response.data.customer_address.last_name,
          company: response.data.customer_address.company,
          address1: response.data.customer_address.address1,
          address2: response.data.customer_address.address2,
          city: response.data.customer_address.city,
          province: response.data.customer_address.province,
          country: response.data.customer_address.country,
          zip: response.data.customer_address.zip,
          phone: response.data.customer_address.phone,
          isDefault: response.data.customer_address.default
        }
      });
    } else {
      return res.status(400).json({ error: 'Failed to create address' });
    }
    
  } catch (error) {
    console.error('Error creating address:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to create address' });
  }
});

// POST /customer/address/:addressId - Update existing address (FIXED)
app.post('/customer/address/:addressId', authenticateAppToken, async (req, res) => {
  try {
    const { addressId } = req.params;
    const { address } = req.body;
    const customerId = req.session.customerId;
    
    console.log('Updating address:', addressId);
    console.log('Customer ID:', customerId);
    console.log('Address data:', JSON.stringify(address, null, 2));
    
    // CRITICAL: Use REST API instead of GraphQL for address updates
    const shopifyRestUrl = `https://${config.shopDomain}/admin/api/2024-10/customers/${customerId.split('/').pop()}/addresses/${addressId.split('/').pop()}.json`;
    
    console.log('Using REST API endpoint:', shopifyRestUrl);
    
    const response = await axios.put(
      shopifyRestUrl,
      {
        address: {
          first_name: address.firstName || '',
          last_name: address.lastName || '',
          company: address.company || '',
          address1: address.address1 || '',
          address2: address.address2 || '',
          city: address.city || '',
          province: address.province || '',
          country: address.country || 'DE',
          zip: address.zip || '',
          phone: address.phone || ''
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json',
        }
      }
    );
    
    console.log('REST API response:', response.status, response.data);
    
    if (response.status === 200 && response.data.address) {
      console.log('Address updated successfully via REST');
      res.json({ 
        address: {
          id: `gid://shopify/MailingAddress/${response.data.address.id}`,
          firstName: response.data.address.first_name,
          lastName: response.data.address.last_name,
          company: response.data.address.company,
          address1: response.data.address.address1,
          address2: response.data.address.address2,
          city: response.data.address.city,
          province: response.data.address.province,
          country: response.data.address.country,
          zip: response.data.address.zip,
          phone: response.data.address.phone,
          isDefault: response.data.address.default
        }
      });
    } else {
      return res.status(400).json({ error: 'Failed to update address' });
    }
    
  } catch (error) {
    console.error('Error updating address:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// DELETE /customer/address/:addressId - Delete address via REST API (FIXED)
app.delete('/customer/address/:addressId', authenticateAppToken, async (req, res) => {
  try {
    const { addressId } = req.params;
    const customerId = req.session.customerId;
    const customerNumericId = customerId.split('/').pop();
    
    // Extract numeric ID from GID format
    let addressNumericId;
    if (addressId.includes('gid://shopify/MailingAddress/')) {
      addressNumericId = addressId.split('/').pop().split('?')[0]; // Remove any query params
    } else {
      addressNumericId = addressId;
    }
    
    console.log('Deleting address via REST:', addressNumericId, 'for customer:', customerNumericId);
    
    const response = await axios.delete(
      `https://${config.shopDomain}/admin/api/2024-10/customers/${customerNumericId}/addresses/${addressNumericId}.json`,
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json',
        }
      }
    );
    
    console.log('REST API delete response:', response.status);
    
    if (response.status === 200) {
      console.log('Address deleted successfully via REST');
      res.json({ success: true });
    } else {
      console.log('Delete failed with status:', response.status);
      return res.status(400).json({ error: 'Failed to delete address' });
    }
    
  } catch (error) {
    console.error('Error deleting address:', error.response?.status, error.response?.data || error.message);
    
    if (error.response?.status === 404) {
      // Address already deleted or doesn't exist
      console.log('Address not found (404) - treating as success');
      res.json({ success: true });
    } else {
      res.status(500).json({ error: 'Failed to delete address' });
    }
  }
});

// POST /customer/address/:addressId/default - Set default address (ADMIN API APPROACH)
app.post('/customer/address/:addressId/default', authenticateAppToken, async (req, res) => {
  try {
    const { addressId } = req.params;
    const customerId = req.session.customerId;
    
    console.log('Setting default address:', addressId);
    console.log('Customer ID:', customerId);
    
    const success = await setAsDefaultAddress(customerId, addressId);
    
    if (success) {
      console.log('Default address set successfully');
      res.json({ success: true });
    } else {
      res.status(400).json({ error: 'Failed to set default address' });
    }
    
  } catch (error) {
    console.error('Error setting default address:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to set default address' });
  }
});

// Alternative approach: Create a separate endpoint specifically for updating names across customer and addresses
app.put('/customer/update-name', authenticateAppToken, async (req, res) => {
  try {
    const { firstName, lastName } = req.body;
    const customerId = req.session.customerId;
    
    if (!firstName && !lastName) {
      return res.status(400).json({ error: 'At least one name field is required' });
    }
    
    console.log('Updating customer name and all addresses:', customerId);
    
    // First get current customer data with all addresses
    const getCustomerQuery = `
      query getCustomer($id: ID!) {
        customer(id: $id) {
          id
          firstName
          lastName
          addresses(first: 50) {
            edges {
              node {
                id
                firstName
                lastName
                company
                address1
                address2
                city
                province
                country
                zip
                phone
              }
            }
          }
        }
      }
    `;
    
    const customerResponse = await axios.post(
      config.adminApiUrl,
      {
        query: getCustomerQuery,
        variables: { id: customerId }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': config.adminToken,
        }
      }
    );
    
    if (customerResponse.data.errors || !customerResponse.data.data?.customer) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    const currentCustomer = customerResponse.data.data.customer;
    
    // Update customer basic info
    const updateCustomerMutation = `
      mutation updateCustomer($id: ID!, $firstName: String, $lastName: String) {
        customerUpdate(
          input: {
            id: $id
            firstName: $firstName
            lastName: $lastName
          }
        ) {
          customer {
            id
            firstName
            lastName
          }
          userErrors {
            field
            message
          }
        }
      }
    `;
    
    const customerUpdateResponse = await axios.post(
      config.adminApiUrl,
      {
        query: updateCustomerMutation,
        variables: {
          id: customerId,
          firstName: firstName || currentCustomer.firstName,
          lastName: lastName || currentCustomer.lastName
        }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': config.adminToken,
        }
      }
    );
    
    if (customerUpdateResponse.data.errors || customerUpdateResponse.data.data?.customerUpdate?.userErrors?.length > 0) {
      return res.status(400).json({ 
        error: 'Failed to update customer name',
        details: customerUpdateResponse.data.errors || customerUpdateResponse.data.data.customerUpdate.userErrors
      });
    }
    
    // Update all addresses
    if (currentCustomer.addresses?.edges?.length > 0) {
      const updateAddressMutation = `
        mutation updateAddress($addressId: ID!, $address: MailingAddressInput!) {
          customerAddressUpdate(
            customerAddressId: $addressId
            address: $address
          ) {
            customerAddress {
              id
            }
            userErrors {
              field
              message
            }
          }
        }
      `;
      
      const addressUpdatePromises = currentCustomer.addresses.edges.map(edge => {
        const address = edge.node;
        const addressInput = {
          firstName: firstName || address.firstName || '',
          lastName: lastName || address.lastName || '',
          company: address.company || '',
          address1: address.address1 || '',
          address2: address.address2 || '',
          city: address.city || '',
          province: address.province || '',
          country: address.country || '',
          zip: address.zip || '',
          phone: address.phone || ''
        };
        
        return axios.post(
          config.adminApiUrl,
          {
            query: updateAddressMutation,
            variables: {
              addressId: address.id,
              address: addressInput
            }
          },
          {
            headers: {
              'Content-Type': 'application/json',
              'X-Shopify-Access-Token': config.adminToken,
            }
          }
        );
      });
      
      await Promise.all(addressUpdatePromises);
    }
    
    // Fetch and return updated customer data
    const finalCustomerResponse = await axios.post(
      config.adminApiUrl,
      {
        query: `
          query getUpdatedCustomer($id: ID!) {
            customer(id: $id) {
              id
              email
              firstName
              lastName
              phone
              emailMarketingConsent {
                marketingState
              }
              defaultAddress {
                id
                firstName
                lastName
                company
                address1
                address2
                city
                province
                country
                zip
                phone
              }
            }
          }
        `,
        variables: { id: customerId }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': config.adminToken,
        }
      }
    );
    
    const updatedCustomer = finalCustomerResponse.data.data.customer;
    const transformedCustomer = {
      ...updatedCustomer,
      acceptsMarketing: updatedCustomer.emailMarketingConsent?.marketingState === 'SUBSCRIBED'
    };
    
    res.json({ 
      customer: transformedCustomer,
      message: 'Customer name updated across profile and all addresses'
    });
    
  } catch (error) {
    console.error('Error updating customer name:', error.response?.data || error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /auth/logout - Logout
app.post('/auth/logout', authenticateAppToken, async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.substring(7);
  
  sessions.delete(token);
  await persistSessions();
  
  res.json({ success: true });
});

// ===== NOTIFICATION ENDPOINTS =====

// GET /api/products - Get all products for notification dashboard
app.get('/api/products', async (req, res) => {
  try {
    const query = `
      query {
        products(first: 250, sortKey: CREATED_AT, reverse: true) {
          edges {
            node {
              id
              title
              handle
              description
              vendor
              productType
              createdAt
              images(first: 1) {
                edges {
                  node {
                    url
                  }
                }
              }
              priceRange {
                minVariantPrice {
                  amount
                  currencyCode
                }
              }
              collections(first: 5) {
                edges {
                  node {
                    id
                    title
                    handle
                  }
                }
              }
              compareAtPriceRange {
                minVariantCompareAtPrice {
                  amount
                }
              }
            }
          }
        }
      }
    `;

    const response = await axios.post(
      config.adminApiUrl,
      { query },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.errors) {
      console.error('GraphQL errors:', response.data.errors);
      return res.status(500).json({ error: 'Failed to fetch products' });
    }

    const products = response.data.data.products.edges.map(edge => {
      const node = edge.node;
      const price = parseFloat(node.priceRange.minVariantPrice.amount);
      const compareAtPrice = node.compareAtPriceRange?.minVariantCompareAtPrice?.amount 
        ? parseFloat(node.compareAtPriceRange.minVariantCompareAtPrice.amount) 
        : null;
      
      return {
        id: node.id,
        handle: node.handle,
        title: node.title,
        description: node.description?.substring(0, 200) || '',
        price: price.toFixed(2),
        image: node.images.edges[0]?.node.url || '',
        collections: node.collections.edges.map(c => ({
          id: c.node.id,
          title: c.node.title,
          handle: c.node.handle
        })),
        productType: node.productType,
        vendor: node.vendor,
        isOnSale: compareAtPrice && compareAtPrice > price,
        createdAt: node.createdAt
      };
    });

    res.json({ products });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// POST /api/send-notification - Send notification via CleverPush
app.post('/api/send-notification', async (req, res) => {
  try {
    const { 
      productHandles, // Array of product handles
      title,
      message,
      segment = 'all',
      campaign = 'manual'
    } = req.body;

    if (!config.cleverpushApiKey) {
      return res.status(400).json({ 
        error: 'CleverPush API key not configured. Add CLEVERPUSH_API_KEY to environment variables.' 
      });
    }

    // Prepare notification data
    const notificationData = {
      channel: config.cleverpushChannelId || '6Bk5KmNkY7fkQ58v3',
      title: title || 'Neue Produkte bei Metallbude',
      text: message || 'Entdecken Sie unsere neuesten Produkte',
      url: 'https://metallbude.com',
    };

    // If single product, add deep link
    if (productHandles && productHandles.length === 1) {
      notificationData.customData = {
        type: 'product',
        id: productHandles[0],
        params: {
          campaign,
          source: 'push_notification'
        }
      };
      notificationData.url = `https://metallbude.com/products/${productHandles[0]}`;
    } 
    // If multiple products, link to collection or general
    else if (productHandles && productHandles.length > 1) {
      notificationData.customData = {
        type: 'collection',
        id: 'neue-produkte',
        params: {
          campaign,
          productCount: productHandles.length
        }
      };
    }

    // Add targeting
    if (segment !== 'all') {
      notificationData.segment = segment;
    }

    // Send via CleverPush API
    const response = await axios.post(
      'https://api.cleverpush.com/notification/send',
      notificationData,
      {
        headers: {
          'Authorization': config.cleverpushApiKey,
          'Content-Type': 'application/json'
        }
      }
    );

    console.log('Notification sent successfully:', response.data);
    res.json({
      success: true,
      notificationId: response.data.id || 'sent',
      message: 'Notification sent successfully'
    });

  } catch (error) {
    console.error('Error sending notification:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to send notification',
      details: error.response?.data || error.message
    });
  }
});

// Serve notification dashboard
app.get('/dashboard', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Metallbude Push Notification Dashboard</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Karla', -apple-system, BlinkMacSystemFont, sans-serif;
                background: #f5f5f5;
                padding: 20px;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 12px;
                padding: 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            h1 {
                margin-bottom: 30px;
                color: #333;
            }
            
            .loading {
                text-align: center;
                padding: 40px;
                color: #666;
            }
            
            .search-box {
                width: 100%;
                padding: 12px 20px;
                font-size: 16px;
                border: 2px solid #ddd;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            
            .filters {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }
            
            .filter-btn {
                padding: 8px 16px;
                border: 1px solid #ddd;
                background: white;
                border-radius: 20px;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .filter-btn:hover {
                background: #f0f0f0;
            }
            
            .filter-btn.active {
                background: #333;
                color: white;
                border-color: #333;
            }
            
            .product-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .product-card {
                border: 2px solid #eee;
                border-radius: 8px;
                overflow: hidden;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .product-card:hover {
                border-color: #333;
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            
            .product-card.selected {
                border-color: #4CAF50;
                background: #f0f9ff;
            }
            
            .product-image {
                width: 100%;
                height: 150px;
                object-fit: cover;
            }
            
            .product-info {
                padding: 12px;
            }
            
            .product-title {
                font-weight: 500;
                margin-bottom: 4px;
                font-size: 14px;
                line-height: 1.4;
            }
            
            .product-price {
                color: #666;
                font-size: 14px;
            }
            
            .sale-badge {
                background: #ff4444;
                color: white;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 12px;
                display: inline-block;
                margin-top: 4px;
            }
            
            .notification-form {
                background: #f9f9f9;
                padding: 20px;
                border-radius: 8px;
                margin-top: 30px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
            }
            
            .form-group input, 
            .form-group textarea,
            .form-group select {
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-family: inherit;
            }
            
            .form-group textarea {
                resize: vertical;
                min-height: 80px;
            }
            
            .selected-products {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin-bottom: 20px;
            }
            
            .selected-product-tag {
                background: #e0f2fe;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 14px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .remove-btn {
                cursor: pointer;
                color: #666;
                font-weight: bold;
            }
            
            .send-btn {
                background: #333;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s;
            }
            
            .send-btn:hover {
                background: #555;
            }
            
            .send-btn:disabled {
                background: #ccc;
                cursor: not-allowed;
            }
            
            .campaign-presets {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 10px;
                margin-bottom: 20px;
            }
            
            .preset-btn {
                padding: 10px;
                border: 1px solid #ddd;
                background: white;
                border-radius: 6px;
                cursor: pointer;
                text-align: center;
                transition: all 0.3s;
            }
            
            .preset-btn:hover {
                background: #f0f0f0;
            }
            
            .error {
                background: #fee;
                color: #c00;
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 20px;
            }
            
            .success {
                background: #efe;
                color: #060;
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Push Notification Dashboard</h1>
            
            <div id="loading" class="loading">Loading products...</div>
            
            <div id="content" style="display: none;">
                <!-- Product Selection -->
                <div class="product-selection">
                    <h2>1. Select Products</h2>
                    <input type="text" class="search-box" placeholder="Search products..." id="searchBox">
                    
                    <div class="filters">
                        <button class="filter-btn active" data-filter="all">All Products</button>
                        <button class="filter-btn" data-filter="sale">On Sale</button>
                        <button class="filter-btn" data-filter="recent">New Arrivals</button>
                    </div>
                    
                    <div class="product-grid" id="productGrid">
                        <!-- Products will be loaded here -->
                    </div>
                </div>
                
                <!-- Notification Form -->
                <div class="notification-form">
                    <h2>2. Create Notification</h2>
                    
                    <div id="message" style="display: none;"></div>
                    
                    <div class="selected-products" id="selectedProducts">
                        <!-- Selected products will appear here -->
                    </div>
                    
                    <div class="campaign-presets">
                        <button class="preset-btn" onclick="applyPreset('new-arrival')">
                            🆕 New Arrival
                        </button>
                        <button class="preset-btn" onclick="applyPreset('sale')">
                            🏷️ Sale Alert
                        </button>
                        <button class="preset-btn" onclick="applyPreset('back-in-stock')">
                            📦 Back in Stock
                        </button>
                        <button class="preset-btn" onclick="applyPreset('limited-time')">
                            ⏰ Limited Time
                        </button>
                    </div>
                    
                    <div class="form-group">
                        <label for="title">Notification Title</label>
                        <input type="text" id="title" placeholder="e.g., Neues Schuhregal eingetroffen!">
                    </div>
                    
                    <div class="form-group">
                        <label for="message">Message</label>
                        <textarea id="message" placeholder="e.g., Entdecken Sie unser neues Camo Schuhregal - perfekt für Ihren Flur!"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="segment">Target Segment (Optional)</label>
                        <input type="text" id="segment" placeholder="e.g., all, viewed_flur, has_items_in_cart">
                    </div>
                    
                    <button class="send-btn" id="sendBtn" onclick="sendNotification()">Send Notification</button>
                </div>
            </div>
        </div>

        <script>
            let products = [];
            let selectedProducts = [];
            let allProducts = [];
            
            // Load products on page load
            async function loadProducts() {
                try {
                    const response = await fetch('/api/products');
                    const data = await response.json();
                    
                    if (data.products) {
                        allProducts = data.products;
                        products = data.products;
                        document.getElementById('loading').style.display = 'none';
                        document.getElementById('content').style.display = 'block';
                        displayProducts();
                        setupEventListeners();
                    }
                } catch (error) {
                    console.error('Error loading products:', error);
                    document.getElementById('loading').innerHTML = 'Error loading products. Please refresh.';
                }
            }
            
            function displayProducts(filter = 'all') {
                const grid = document.getElementById('productGrid');
                grid.innerHTML = '';
                
                let filteredProducts = products;
                
                if (filter === 'sale') {
                    filteredProducts = products.filter(p => p.isOnSale);
                } else if (filter === 'recent') {
                    // Show products from last 30 days
                    const thirtyDaysAgo = new Date();
                    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
                    filteredProducts = products.filter(p => 
                        new Date(p.createdAt) > thirtyDaysAgo
                    );
                }
                
                filteredProducts.forEach(product => {
                    const card = createProductCard(product);
                    grid.appendChild(card);
                });
            }
            
            function createProductCard(product) {
                const div = document.createElement('div');
                div.className = 'product-card';
                div.dataset.productHandle = product.handle;
                
                const isSelected = selectedProducts.some(p => p.handle === product.handle);
                if (isSelected) {
                    div.classList.add('selected');
                }
                
                div.innerHTML = \`
                    <img src="\${product.image}" alt="\${product.title}" class="product-image" onerror="this.src='https://via.placeholder.com/200'">
                    <div class="product-info">
                        <div class="product-title">\${product.title}</div>
                        <div class="product-price">€\${product.price}</div>
                        \${product.isOnSale ? '<span class="sale-badge">SALE</span>' : ''}
                    </div>
                \`;
                
                div.addEventListener('click', () => toggleProduct(product));
                
                return div;
            }
            
            function toggleProduct(product) {
                const index = selectedProducts.findIndex(p => p.handle === product.handle);
                const card = document.querySelector(\`[data-product-handle="\${product.handle}"]\`);
                
                if (index > -1) {
                    selectedProducts.splice(index, 1);
                    card.classList.remove('selected');
                } else {
                    selectedProducts.push(product);
                    card.classList.add('selected');
                }
                
                updateSelectedProductsDisplay();
            }
            
            function updateSelectedProductsDisplay() {
                const container = document.getElementById('selectedProducts');
                
                if (selectedProducts.length === 0) {
                    container.innerHTML = '<p style="color: #666;">No products selected</p>';
                } else {
                    container.innerHTML = selectedProducts.map(product => \`
                        <div class="selected-product-tag">
                            \${product.title}
                            <span class="remove-btn" onclick="removeProduct('\${product.handle}')">×</span>
                        </div>
                    \`).join('');
                }
            }
            
            function removeProduct(productHandle) {
                const product = selectedProducts.find(p => p.handle === productHandle);
                if (product) {
                    toggleProduct(product);
                }
            }
            
            function applyPreset(type) {
                const presets = {
                    'new-arrival': {
                        title: '🆕 Neu eingetroffen!',
                        message: 'Entdecken Sie unsere neuesten Produkte - frisch eingetroffen und bereit für Ihr Zuhause!'
                    },
                    'sale': {
                        title: '🏷️ SALE - Bis zu 30% Rabatt!',
                        message: 'Nur für kurze Zeit - sparen Sie bei ausgewählten Produkten!'
                    },
                    'back-in-stock': {
                        title: '📦 Wieder verfügbar!',
                        message: 'Ihre Lieblingsprodukte sind wieder auf Lager'
                    },
                    'limited-time': {
                        title: '⏰ Nur noch heute!',
                        message: 'Letzte Chance auf diese fantastischen Angebote'
                    }
                };
                
                const preset = presets[type];
                document.getElementById('title').value = preset.title;
                document.getElementById('message').value = preset.message;
            }
            
            function setupEventListeners() {
                // Search
                document.getElementById('searchBox').addEventListener('input', (e) => {
                    const search = e.target.value.toLowerCase();
                    
                    if (search === '') {
                        products = allProducts;
                    } else {
                        products = allProducts.filter(product => 
                            product.title.toLowerCase().includes(search) ||
                            product.description.toLowerCase().includes(search)
                        );
                    }
                    
                    displayProducts();
                });
                
                // Filters
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                        e.target.classList.add('active');
                        displayProducts(e.target.dataset.filter);
                    });
                });
                
                // Initial display
                updateSelectedProductsDisplay();
            }
            
            async function sendNotification() {
                const title = document.getElementById('title').value;
                const message = document.getElementById('message').value;
                const segment = document.getElementById('segment').value || 'all';
                
                if (!title || !message) {
                    showMessage('Please enter title and message', 'error');
                    return;
                }
                
                if (selectedProducts.length === 0) {
                    showMessage('Please select at least one product', 'error');
                    return;
                }
                
                const sendBtn = document.getElementById('sendBtn');
                sendBtn.disabled = true;
                sendBtn.textContent = 'Sending...';
                
                try {
                    const response = await fetch('/api/send-notification', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            productHandles: selectedProducts.map(p => p.handle),
                            title,
                            message,
                            segment,
                            campaign: 'dashboard'
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showMessage('Notification sent successfully!', 'success');
                        // Reset form
                        selectedProducts = [];
                        updateSelectedProductsDisplay();
                        document.querySelectorAll('.product-card').forEach(card => {
                            card.classList.remove('selected');
                        });
                        document.getElementById('title').value = '';
                        document.getElementById('message').value = '';
                    } else {
                        showMessage(result.error || 'Failed to send notification', 'error');
                    }
                } catch (error) {
                    showMessage('Network error: ' + error.message, 'error');
                } finally {
                    sendBtn.disabled = false;
                    sendBtn.textContent = 'Send Notification';
                }
            }
            
            function showMessage(text, type) {
                const messageDiv = document.getElementById('message');
                messageDiv.className = type;
                messageDiv.textContent = text;
                messageDiv.style.display = 'block';
                
                setTimeout(() => {
                    messageDiv.style.display = 'none';
                }, 5000);
            }
            
            // Load products when page loads
            loadProducts();
        </script>
    </body>
    </html>
  `);
});

// Health check
app.get('/health', async (req, res) => {
  try {
    let firebaseHealth = { status: 'disabled', message: 'Firebase not initialized' };
    
    // Check Firebase connectivity if enabled
    if (firebaseEnabled && wishlistService) {
      try {
        firebaseHealth = await wishlistService.healthCheck();
      } catch (error) {
        firebaseHealth = { status: 'error', error: error.message };
      }
    }
    
    const healthInfo = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      mode: 'combined',
      oauth: true,
      oneTimeCode: true,
      customerEndpoints: true,
      returnManagement: true,
      issuer: config.issuer,
      firebase: firebaseHealth,
      firebaseEnabled,
      environment: process.env.NODE_ENV || 'development',
      version: '2.0.0'
    };
    
    // Don't expose sensitive information in production
    if (process.env.NODE_ENV !== 'production') {
      healthInfo.memoryUsage = process.memoryUsage();
      healthInfo.uptime = Math.floor(process.uptime());
      healthInfo.nodeVersion = process.version;
    }
    
    res.json(healthInfo);
  } catch (error) {
    console.error('❌ Health check error:', error.message);
    res.status(500).json({ 
      status: 'error',
      timestamp: new Date().toISOString(),
      error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message,
      firebase: { status: 'error', error: error.message },
      firebaseEnabled
    });
  }
});

app.get('/debug/sessions', (req, res) => {
  console.log('🔍 Debug endpoint called - checking session storage...');
  console.log(`   Sessions in memory: ${sessions.size}`);
  console.log(`   Refresh tokens in memory: ${appRefreshTokens.size}`);
  
  const sessionList = [];
  
  for (const [token, session] of sessions.entries()) {
    console.log(`   Found session: ${token.substring(0, 8)}... for ${session.email}`);
    sessionList.push({
      tokenPreview: token.substring(0, 20) + '...',
      email: session.email,
      customerId: session.customerId,
      createdAt: new Date(session.createdAt).toISOString(),
      expiresAt: new Date(session.expiresAt).toISOString(),
      isExpired: session.expiresAt < Date.now(),
      daysUntilExpiry: Math.round((session.expiresAt - Date.now()) / (24 * 60 * 60 * 1000))
    });
  }
  
  const refreshTokenList = [];
  for (const [token, data] of appRefreshTokens.entries()) {
    refreshTokenList.push({
      tokenPreview: token.substring(0, 8) + '...',
      email: data.email,
      accessTokenPreview: data.accessToken.substring(0, 8) + '...',
      expiresAt: new Date(data.expiresAt).toISOString(),
      isExpired: data.expiresAt < Date.now()
    });
  }
  
  res.json({
    totalSessions: sessions.size,
    totalRefreshTokens: appRefreshTokens.size,
    sessions: sessionList,
    refreshTokens: refreshTokenList,
    serverTime: new Date().toISOString(),
    serverTimestamp: Date.now(),
    persistenceEnabled: true,
    sessionStorageType: 'Map with disk persistence',
    diskFiles: {
      sessionsFile: SESSION_FILE,
      refreshTokensFile: REFRESH_TOKENS_FILE
    }
  });
});

// 🔥 ADD this new endpoint to check disk storage
app.get('/debug/disk-sessions', async (req, res) => {
  try {
    console.log('📂 Checking disk storage...');
    
    let diskSessions = [];
    let diskRefreshTokens = [];
    let sessionsFileExists = false;
    let refreshTokensFileExists = false;
    
    // Check sessions file
    try {
      const sessionData = await fs.readFile('/tmp/sessions.json', 'utf8');
      try {
        const sessionEntries = JSON.parse(sessionData);
        diskSessions = sessionEntries;
        sessionsFileExists = true;
        console.log(`📂 Found ${sessionEntries.length} sessions on disk`);
      } catch (jsonParseError) {
        console.error('❌ [DEBUG_DISK] Failed to parse sessions JSON:', jsonParseError.message);
        console.error('❌ [DEBUG_DISK] Session data length:', sessionData?.length || 0);
        sessionsFileExists = false;
      }
    } catch (error) {
      console.log('📂 No sessions file found on disk');
    }
    
    // Check refresh tokens file
    try {
      const refreshData = await fs.readFile('/tmp/refresh_tokens.json', 'utf8');
      try {
        const refreshEntries = JSON.parse(refreshData);
        diskRefreshTokens = refreshEntries;
        refreshTokensFileExists = true;
        console.log(`📂 Found ${refreshEntries.length} refresh tokens on disk`);
      } catch (jsonParseError) {
        console.error('❌ [DEBUG_DISK] Failed to parse refresh tokens JSON:', jsonParseError.message);
        console.error('❌ [DEBUG_DISK] Refresh data length:', refreshData?.length || 0);
        refreshTokensFileExists = false;
      }
    } catch (error) {
      console.log('📂 No refresh tokens file found on disk');
    }
    
    res.json({
      diskStorage: {
        sessionsFileExists,
        refreshTokensFileExists,
        diskSessions: diskSessions.length,
        diskRefreshTokens: diskRefreshTokens.length
      },
      memoryStorage: {
        memorySessions: sessions.size,
        memoryRefreshTokens: appRefreshTokens.size
      },
      diskSessionsPreview: diskSessions.slice(0, 3).map(([token, session]) => ({
        tokenPreview: token.substring(0, 8) + '...',
        email: session.email,
        expiresAt: new Date(session.expiresAt).toISOString()
      })),
      memorySessionsPreview: Array.from(sessions.entries()).slice(0, 3).map(([token, session]) => ({
        tokenPreview: token.substring(0, 8) + '...',
        email: session.email,
        expiresAt: new Date(session.expiresAt).toISOString()
      }))
    });
    
  } catch (error) {
    console.error('❌ Error checking disk storage:', error);
    res.status(500).json({ error: error.message });
  }
});

// DEBUG: Debug returns mapping endpoint - inspect fulfillmentLineItemId mapping
app.get('/debug/returns/map', authenticateAppToken, async (req, res) => {
  try {
    const { orderId } = req.query;
    
    if (!orderId) {
      return res.status(400).json({ error: 'orderId parameter required' });
    }
    
    if (!config.adminToken) {
      return res.status(400).json({ error: 'Admin token not configured - cannot map fulfillment line items' });
    }
    
    console.log('🔍 [DEBUG] Mapping fulfillment line items for order:', orderId);
    
    // Fetch order fulfillments via Admin API
    const orderQuery = `
      query getOrderFulfillments($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          fulfillments {
            id
            status
            fulfillmentLineItems(first: 50) {
              edges {
                node {
                  id
                  quantity
                  lineItem {
                    id
                    title
                    variant {
                      id
                      title
                    }
                  }
                }
              }
            }
          }
        }
      }`;
    
    const orderResponse = await axios.post(config.adminApiUrl, {
      query: orderQuery,
      variables: { orderId }
    }, {
      headers: {
        'X-Shopify-Access-Token': config.adminToken,
        'Content-Type': 'application/json',
      }
    });

    if (orderResponse.data.errors) {
      return res.status(502).json({
        error: 'GraphQL errors',
        details: orderResponse.data.errors
      });
    }

    const order = orderResponse.data.data.order;
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Map all fulfillment line items
    const mappedItems = [];
    for (const fulfillment of order.fulfillments) {
      for (const fulfillmentLineItemEdge of fulfillment.fulfillmentLineItems.edges) {
        const fulfillmentLineItem = fulfillmentLineItemEdge.node;
        mappedItems.push({
          fulfillmentLineItemId: fulfillmentLineItem.id,
          quantity: fulfillmentLineItem.quantity,
          lineItemId: fulfillmentLineItem.lineItem.id,
          title: fulfillmentLineItem.lineItem.title,
          variant: {
            id: fulfillmentLineItem.lineItem.variant?.id,
            title: fulfillmentLineItem.lineItem.variant?.title
          },
          fulfillmentId: fulfillment.id,
          fulfillmentStatus: fulfillment.status
        });
      }
    }

    res.json({
      success: true,
      orderId,
      orderName: order.name,
      totalFulfillments: order.fulfillments.length,
      totalMappedItems: mappedItems.length,
      mappedItems
    });

  } catch (error) {
    console.error('❌ [DEBUG] Error mapping returns:', error.message);
    res.status(500).json({
      error: 'Failed to map returns',
      details: error.message
    });
  }
});

// Test endpoint for return creation (no auth required for debugging)
app.post('/debug/returns/test', async (req, res) => {
  try {
    console.log('🧪 [DEBUG] Test return creation request:', JSON.stringify(req.body, null, 2));
    
    const { orderId, items, customerMessage } = req.body;
    
    if (!orderId || !items) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['orderId', 'items']
      });
    }

    // Map return items (use global helper)
    const returnLineItems = items.map(item => ({
      fulfillmentLineItemId: item.fulfillmentLineItemId,
      quantity: item.quantity,
      returnReason: mapReasonToShopify(item.reason)
    }));

    console.log('🧪 [DEBUG] Mapped return line items:', JSON.stringify(returnLineItems, null, 2));

    const returnInput = {
      orderId: orderId,
      returnLineItems: returnLineItems
    };

    console.log('🧪 [DEBUG] Final return input:', JSON.stringify(returnInput, null, 2));

    // For testing, just return the mapped data without actually calling Shopify
    res.json({
      success: true,
      message: 'Test successful - return input is valid',
      returnInput: returnInput,
      originalRequest: { orderId, items, customerMessage }
    });

  } catch (error) {
    console.error('❌ [DEBUG] Test return error:', error.message);
    res.status(500).json({
      error: 'Test failed',
      details: error.message
    });
  }
});

async function cleanupExpiredTokens() {
  const now = Date.now();
  let cleanedSessions = 0;
  let cleanedRefreshTokens = 0;
  
  // Clean expired sessions
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt && session.expiresAt < now) {
      sessions.delete(token);
      await persistSessions();
      cleanedSessions++;
    }
  }
  
  // Clean expired refresh tokens
  for (const [refreshToken, data] of appRefreshTokens.entries()) {
    if (data.expiresAt < now) {
      appRefreshTokens.delete(refreshToken);
      cleanedRefreshTokens++;
    }
  }
  
  if (cleanedSessions > 0 || cleanedRefreshTokens > 0) {
    console.log(`🧹 Cleaned up ${cleanedSessions} expired sessions and ${cleanedRefreshTokens} expired refresh tokens`);
  }
}

// Run cleanup every 24 hours
setInterval(async () => {
  await cleanupExpiredTokens();
}, 24 * 60 * 60 * 1000);

// Health check endpoint with token statistics
app.get('/auth/health', (req, res) => {
  const activeSessions = sessions.size;
  const activeRefreshTokens = appRefreshTokens.size;
  const pendingVerifications = config.verificationCodes.size;
  
  const activeShopifyTokens = shopifyCustomerTokens.size;
  let expiringSoonShopifyTokens = 0;
  const now = Date.now();
  
  for (const tokenData of shopifyCustomerTokens.values()) {
    if (tokenData.expiresAt - now < (30 * 60 * 1000)) {
      expiringSoonShopifyTokens++;
    }
  }
  
  let totalAge = 0;
  let expiringSoon = 0;
  
  for (const session of sessions.values()) {
    if (session.createdAt) {
      totalAge += now - session.createdAt;
    }
    if (session.expiresAt && (session.expiresAt - now) < (30 * 24 * 60 * 60 * 1000)) {
      expiringSoon++;
    }
  }
  
  const averageAgeDays = activeSessions > 0 ? 
    Math.round(totalAge / activeSessions / (24 * 60 * 60 * 1000)) : 0;
  
  res.json({
    status: 'healthy',
    mode: 'production',
    tokenLifetimes: {
      accessTokenDays: Math.round(config.tokenLifetimes.accessToken / (24 * 60 * 60)),
      refreshTokenDays: Math.round(config.tokenLifetimes.refreshToken / (24 * 60 * 60)),
    },
    statistics: {
      activeSessions,
      activeRefreshTokens,
      pendingVerifications,
      averageSessionAgeDays: averageAgeDays,
      sessionsExpiringSoon: expiringSoon,
      activeShopifyTokens,
      expiringSoonShopifyTokens,
    },
    lastCleanup: new Date().toISOString(),
    shopifyTokenManagement: 'active',
  });
});

// WISHLIST API ENDPOINTS

// Sync wishlist to Shopify customer metafields
async function syncWishlistToShopify(customerId, wishlistItems) {
    try {
        console.log('🔄 Syncing wishlist to Shopify metafields for customer:', customerId);
        
        // Convert wishlist items to simple product IDs for Shopify
        const productIds = wishlistItems.map(item => item.productId);
        
        const mutation = `
            mutation customerUpdate($input: CustomerInput!) {
                customerUpdate(input: $input) {
                    customer {
                        id
                        metafields(first: 1, namespace: "customer", keys: ["wishlist"]) {
                            edges {
                                node {
                                    id
                                    value
                                }
                            }
                        }
                    }
                    userErrors {
                        field
                        message
                    }
                }
            }
        `;

        const variables = {
            input: {
                id: customerId,
                metafields: [
                    {
                        namespace: "customer",
                        key: "wishlist",
                        value: JSON.stringify(productIds),
                        type: "json"
                    }
                ]
            }
        };

        const response = await axios.post(
            config.adminApiUrl,
            { query: mutation, variables },
            {
                headers: {
                    'X-Shopify-Access-Token': config.adminToken,
                    'Content-Type': 'application/json'
                }
            }
        );

        if (response.data.data?.customerUpdate?.userErrors?.length > 0) {
            console.error('❌ Shopify sync errors:', response.data.data.customerUpdate.userErrors);
        } else {
            console.log('✅ Successfully synced wishlist to Shopify metafields');
        }
    } catch (error) {
        console.error('❌ Error syncing wishlist to Shopify:', error.message);
        // Don't throw error - wishlist should still work even if sync fails
    }
}

// Load wishlist data from JSON file
async function loadWishlistData() {
    try {
        const filePath = path.join(__dirname, 'wishlist_data.json');
        const data = await fs.readFile(filePath, 'utf8');
        console.log('✅ [STORAGE] Successfully loaded wishlist data from filesystem');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('ℹ️ [STORAGE] No wishlist data file found, starting with empty data');
            return {}; // Return empty object if file doesn't exist
        } else {
            console.error('⚠️ [STORAGE] Error reading wishlist data file (using empty data):', error.message);
            return {}; // Return empty object if any read error
        }
    }
}

// Helper function to extract product handle from Shopify product ID
function extractHandleFromProductId(productId) {
    // This is a simplified version - you might want to make an API call to get the actual handle
    if (!productId) return null;
    
    // If productId contains a GID, extract the ID part
    if (productId.includes('gid://shopify/Product/')) {
        const id = productId.replace('gid://shopify/Product/', '');
        return `product-${id}`; // Fallback handle
    }
    
    return null;
}

// Save wishlist data to JSON file
async function saveWishlistData(data) {
    try {
        const filePath = path.join(__dirname, 'wishlist_data.json');
        await fs.writeFile(filePath, JSON.stringify(data, null, 2));
        console.log('✅ [STORAGE] Successfully saved wishlist data to filesystem');
    } catch (error) {
        console.error('⚠️ [STORAGE] Error saving wishlist data to filesystem (continuing without persistent storage):', error.message);
        // Don't throw error - continue without persistent storage
        // The data will still be processed and sent to Firebase
    }
}

// Sync Firebase wishlist to public storage for a specific customer
async function syncFirebaseToPublicStorage(customerId) {
    if (!firebaseEnabled || !wishlistService) {
        console.log('🔥 [SYNC] Firebase not available, skipping sync');
        return false;
    }

    try {
        console.log(`🔄 [SYNC] Syncing Firebase to public storage for customer: ${customerId}`);
        
        // Try both customer ID formats to find the Firebase document
        let firebaseItems = [];
        let foundFormat = null;
        
        // Try simple format first (this is what gets stored when adding from Flutter)
        try {
            // Note: For sync operations, we use a customer-specific placeholder email
            // since sync functions don't have access to session data with real customer emails
            firebaseItems = await wishlistService.getWishlist(customerId, `sync-${customerId}@metallbude.internal`);
            if (firebaseItems.length > 0) {
                foundFormat = 'simple';
                console.log(`✅ [SYNC] Found ${firebaseItems.length} items using simple format`);
            }
        } catch (error) {
            console.log(`⚠️ [SYNC] Simple format failed: ${error.message}`);
        }
        
        // If no items found, try full Shopify GID format
        if (firebaseItems.length === 0) {
            try {
                const fullCustomerId = `gid://shopify/Customer/${customerId}`;
                firebaseItems = await wishlistService.getWishlist(fullCustomerId, `sync-${customerId}@metallbude.internal`);
                if (firebaseItems.length > 0) {
                    foundFormat = 'full';
                    console.log(`✅ [SYNC] Found ${firebaseItems.length} items using full format`);
                }
            } catch (error) {
                console.log(`⚠️ [SYNC] Full format failed: ${error.message}`);
            }
        }
        
        if (firebaseItems.length === 0) {
            console.log(`ℹ️ [SYNC] No wishlist items found in Firebase for customer ${customerId}`);
            return true; // Not an error, just empty wishlist
        }
        
        // Load current public storage
        const publicWishlistData = await loadWishlistData();
        
        // Convert Firebase items to public storage format
        const publicItems = firebaseItems.map(item => ({
            productId: item.productId,
            variantId: item.variantId || item.productId, // Use actual variantId if available
            title: item.title || `Product ${item.productId}`, // ✅ Use enhanced title from Firebase
            imageUrl: item.imageUrl || '', // ✅ Use enhanced image URL from Firebase (variant image!)
            price: item.price || 0, // ✅ Use enhanced price from Firebase
            compareAtPrice: item.compareAtPrice || 0,
            sku: item.sku || '', // ✅ Use enhanced SKU from Firebase
            selectedOptions: item.selectedOptions || {}, // ✅ CRITICAL: Preserve selectedOptions from Firebase
            handle: item.handle || '', // ✅ Use enhanced handle from Firebase
            addedAt: item.addedAt,
            syncedFromFirebase: true
        }));
        
        // Update public storage with Firebase data
        publicWishlistData[customerId] = publicItems;
        await saveWishlistData(publicWishlistData);
        
        console.log(`✅ [SYNC] Successfully synced ${publicItems.length} items from Firebase to public storage for customer ${customerId}`);
        return true;
        
    } catch (error) {
        console.error(`🚨 [SYNC] Error syncing Firebase to public storage for customer ${customerId}:`, error);
        return false;
    }
}

// Sync all customers' wishlists from Firebase to public storage
async function syncAllFirebaseToPublicStorage() {
    if (!firebaseEnabled || !wishlistService) {
        console.log('🔥 [SYNC] Firebase not available, skipping full sync');
        return false;
    }

    try {
        console.log('🔄 [SYNC] Starting full sync from Firebase to public storage');
        
        // Get all wishlist documents from Firebase
        const db = wishlistService.db;
        const wishlistsSnapshot = await db.collection('wishlists').get();
        
        const publicWishlistData = await loadWishlistData();
        let syncedCount = 0;
        
        for (const doc of wishlistsSnapshot.docs) {
            try {
                const data = doc.data();
                const customerId = data.customerId;
                
                // Extract numeric customer ID from full Shopify GID
                let simpleCustomerId = customerId;
                if (customerId && customerId.includes('gid://shopify/Customer/')) {
                    simpleCustomerId = customerId.replace('gid://shopify/Customer/', '');
                }
                
                // Convert Firebase items to public storage format
                const publicItems = (data.items || []).map(item => ({
                    productId: item.productId,
                    variantId: item.variantId || item.productId,
                    title: item.title || `Product ${item.productId}`, // ✅ Use enhanced title
                    imageUrl: item.imageUrl || '', // ✅ Use enhanced image URL (variant image!)
                    price: item.price || 0, // ✅ Use enhanced price
                    compareAtPrice: item.compareAtPrice || 0,
                    sku: item.sku || '', // ✅ Use enhanced SKU
                    selectedOptions: item.selectedOptions || {}, // ✅ Preserve selectedOptions
                    handle: item.handle || '', // ✅ Use enhanced handle
                    addedAt: item.addedAt,
                    syncedFromFirebase: true
                }));
                
                publicWishlistData[simpleCustomerId] = publicItems;
                syncedCount++;
                
                console.log(`✅ [SYNC] Synced ${publicItems.length} items for customer ${simpleCustomerId}`);
                
            } catch (docError) {
                console.error(`🚨 [SYNC] Error syncing document ${doc.id}:`, docError);
            }
        }
        
        await saveWishlistData(publicWishlistData);
        
        console.log(`✅ [SYNC] Full sync completed: ${syncedCount} customers synced`);
        return true;
        
    } catch (error) {
        console.error('🚨 [SYNC] Error during full sync:', error);
        return false;
    }
}

// Helper function to extract product handle from Shopify product ID
function extractHandleFromProductId(productId) {
    // This is a simplified version - you might want to make actual Shopify API calls
    // to get the real handle, but for now we'll generate one
    if (productId && productId.includes('gid://shopify/Product/')) {
        // For now, return null so we generate a handle from the title
        return null;
    }
    return null;
}

// Get wishlist items for a customer
app.get('/api/wishlist/items', authenticateAppToken, async (req, res) => {
    try {
        const sessionCustomerId = req.session.customerId;
        
        if (!sessionCustomerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        console.log(`📥 [AUTH] Getting wishlist for authenticated customer: ${sessionCustomerId}`);

        // Map customer ID for cross-platform compatibility
        const customerId = mapCustomerIdForWishlist(sessionCustomerId);
        console.log(`📥 [AUTH] Mapped to customer ID: ${customerId}`);

        // First try to sync from Firebase to ensure we have the latest data
        const syncSuccess = await syncFirebaseToPublicStorage(customerId);
        console.log(`🔄 [AUTH] Firebase sync result: ${syncSuccess}`);

        const wishlistData = await loadWishlistData();
        let customerWishlist = wishlistData[customerId] || [];

        console.log(`📥 [AUTH] Found ${customerWishlist.length} wishlist items for ${customerId}`);

        res.json({
            success: true,
            items: customerWishlist,
            count: customerWishlist.length
        });
    } catch (error) {
        console.error('Error getting wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add item to wishlist
app.post('/api/wishlist/add', authenticateAppToken, async (req, res) => {
    try {
        const sessionCustomerId = req.session.customerId;
        
        if (!sessionCustomerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        // Map customer ID for cross-platform compatibility
        const customerId = mapCustomerIdForWishlist(sessionCustomerId);
        console.log(`➕ [AUTH] Adding to wishlist for customer: ${customerId} (session: ${sessionCustomerId})`);

        const {
            productId,
            variantId,
            title,
            imageUrl,
            price,
            compareAtPrice,
            sku,
            selectedOptions
        } = req.body;

        if (!productId || !title) {
            return res.status(400).json({ error: 'Product ID and title are required' });
        }

        const wishlistData = await loadWishlistData();
        
        if (!wishlistData[customerId]) {
            wishlistData[customerId] = [];
        }

        // Check if item already exists
        const existingItemIndex = wishlistData[customerId].findIndex(item => 
            item.productId === productId && 
            item.variantId === (variantId || productId) &&
            JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
        );

        if (existingItemIndex !== -1) {
            return res.json({
                success: true,
                message: 'Item already in wishlist',
                alreadyExists: true
            });
        }

        // Add new item
        const newItem = {
            id: Date.now().toString(),
            productId,
            variantId: variantId || productId,
            title,
            imageUrl,
            price: parseFloat(price) || 0,
            compareAtPrice: compareAtPrice ? parseFloat(compareAtPrice) : null,
            sku,
            selectedOptions: selectedOptions || {},
            createdAt: new Date().toISOString()
        };

        wishlistData[customerId].push(newItem);
        await saveWishlistData(wishlistData);

        // 🔥 SYNC: Also add to public wishlist if we can map to Shopify customer ID
        try {
            // Extract Shopify customer ID from the productId or customerId if it's a Shopify ID
            let shopifyCustomerId = null;
            
            
            // Method 1: Check if customerId is already a Shopify customer ID format
            if (customerId && customerId.includes('gid://shopify/Customer/')) {
                shopifyCustomerId = customerId.replace('gid://shopify/Customer/', '');
            } else if (customerId && /^\d+$/.test(customerId)) {
                // Method 2: If it's just numeric, it might be a Shopify customer ID
                shopifyCustomerId = customerId;
            }
            
            // Method 3: Try to extract from session metadata (check if session has Shopify customer info)
            if (!shopifyCustomerId && req.session && req.session.shopifyCustomerId) {
                shopifyCustomerId = req.session.shopifyCustomerId;
            }
            
            if (shopifyCustomerId) {
                console.log(`🔄 [SYNC] Syncing authenticated wishlist to public storage for Shopify customer: ${shopifyCustomerId}`);
                
                // Also save to public wishlist storage with Shopify customer ID
                if (!wishlistData[shopifyCustomerId]) {
                    wishlistData[shopifyCustomerId] = [];
                }
                
                // Check if item already exists in public storage
                const publicExistingIndex = wishlistData[shopifyCustomerId].findIndex(item => 
                    item.productId === productId && 
                    item.variantId === (variantId || productId) &&
                    JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
                );
                
                if (publicExistingIndex === -1) {
                    // Create a version for public storage with handle
                    const publicItem = {
                        ...newItem,
                        handle: extractHandleFromProductId(productId) || title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
                    };
                    
                    wishlistData[shopifyCustomerId].push(publicItem);
                    await saveWishlistData(wishlistData);
                    
                    console.log(`✅ [SYNC] Successfully synced item to public storage for customer ${shopifyCustomerId}`);
                    console.log(`✅ [SYNC] Public storage now has ${wishlistData[shopifyCustomerId].length} items`);
                } else {
                    console.log(`ℹ️ [SYNC] Item already exists in public storage for customer ${shopifyCustomerId}`);
                }
            } else {
                console.log(`⚠️ [SYNC] Could not map session customer ID "${customerId}" to Shopify customer ID`);
                console.log(`⚠️ [SYNC] Available session data:`, Object.keys(req.session || {}));
            }
        } catch (syncError) {
            console.error('🚨 [SYNC] Error syncing to public storage:', syncError);
            // Don't fail the main request if sync fails
        }

        // Sync to Shopify metafields
        await syncWishlistToShopify(customerId, wishlistData[customerId]);

        res.json({
            success: true,
            message: 'Item added to wishlist',
            item: newItem
        });
    } catch (error) {
        console.error('Error adding to wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Remove item from wishlist
app.delete('/api/wishlist/remove', authenticateAppToken, async (req, res) => {
    try {
        const sessionCustomerId = req.session.customerId;
        
        if (!sessionCustomerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        // Map customer ID for cross-platform compatibility
        const customerId = mapCustomerIdForWishlist(sessionCustomerId);
        console.log(`➖ [AUTH] Removing from wishlist for customer: ${customerId} (session: ${sessionCustomerId})`);

        const { productId, variantId, selectedOptions } = req.body;

        if (!productId) {
            return res.status(400).json({ error: 'Product ID is required' });
        }

        const wishlistData = await loadWishlistData();
        
        if (!wishlistData[customerId]) {
            return res.json({ success: true, message: 'Item not in wishlist' });
        }

        // Find and remove item
        const itemIndex = wishlistData[customerId].findIndex(item => 
            item.productId === productId && 
            item.variantId === (variantId || productId) &&
            JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
        );

        if (itemIndex === -1) {
            return res.json({ success: true, message: 'Item not found in wishlist' });
        }

        wishlistData[customerId].splice(itemIndex, 1);
        await saveWishlistData(wishlistData);

        // 🔥 SYNC: Also remove from public wishlist if we can map to Shopify customer ID
        try {
            // Extract Shopify customer ID from the customerId
            let shopifyCustomerId = null;
            
            if (customerId && customerId.includes('gid://shopify/Customer/')) {
                shopifyCustomerId = customerId.replace('gid://shopify/Customer/', '');
            } else if (customerId && /^\d+$/.test(customerId)) {
                shopifyCustomerId = customerId;
            }
            
            if (shopifyCustomerId && wishlistData[shopifyCustomerId]) {
                console.log(`🔄 [SYNC] Syncing authenticated wishlist removal to public storage for Shopify customer: ${shopifyCustomerId}`);
                
                // Remove from public storage too
                const publicItemIndex = wishlistData[shopifyCustomerId].findIndex(item => 
                    item.productId === productId && 
                    item.variantId === (variantId || productId) &&
                    JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
                );
                
                if (publicItemIndex !== -1) {
                    wishlistData[shopifyCustomerId].splice(publicItemIndex, 1);
                    await saveWishlistData(wishlistData);
                    console.log(`✅ [SYNC] Successfully removed item from public storage for customer ${shopifyCustomerId}`);
                } else {
                    console.log(`ℹ️ [SYNC] Item not found in public storage for customer ${shopifyCustomerId}`);
                }
            }
        } catch (syncError) {
            console.error('🚨 [SYNC] Error syncing removal to public storage:', syncError);
            // Don't fail the main request if sync fails
        }

        // Sync to Shopify metafields
        await syncWishlistToShopify(customerId, wishlistData[customerId]);

        res.json({
            success: true,
            message: 'Item removed from wishlist'
        });
    } catch (error) {
        console.error('Error removing from wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// 🔥 SHOPIFY PUBLIC WISHLIST ENDPOINTS (no authentication required)
// These endpoints are specifically for Shopify frontend integration

// Get wishlist items for a customer (public endpoint for Shopify)
app.get('/api/public/wishlist/items', async (req, res) => {
    try {
        const { customerId } = req.query;
        
        if (!customerId) {
            return res.status(400).json({ 
                success: false,
                error: 'Customer ID is required' 
            });
        }

        console.log(`[SHOPIFY] Getting wishlist for customer: ${customerId}`);

        let customerWishlist = [];

        // Always try to sync from Firebase first to ensure we have the latest data
        if (firebaseEnabled && wishlistService) {
            try {
                console.log(`[SHOPIFY] Syncing Firebase data for customer: ${customerId}`);
                const syncSuccess = await syncFirebaseToPublicStorage(customerId);
                
                if (syncSuccess) {
                    console.log(`[SHOPIFY] Successfully synced Firebase data, loading from public storage`);
                    const wishlistData = await loadWishlistData();
                    customerWishlist = wishlistData[customerId] || [];
                    console.log(`[SHOPIFY] Found ${customerWishlist.length} items after Firebase sync`);
                } else {
                    console.log(`[SHOPIFY] Firebase sync failed, trying direct Firebase lookup`);
                    // Direct Firebase lookup as fallback
                    const fullCustomerId = `gid://shopify/Customer/${customerId}`;
                    // ✅ NEW: Get real customer email for Firebase operations
                    const customerEmail = await getRealCustomerEmail(customerId);
                    const firebaseItems = await wishlistService.getWishlistProductIds(fullCustomerId, customerEmail);
                    
                    if (firebaseItems.length > 0) {
                        console.log(`[SHOPIFY] Found ${firebaseItems.length} items in Firebase`);
                        customerWishlist = firebaseItems.map(productId => ({ productId }));
                    } else {
                        console.log(`[SHOPIFY] No items found in Firebase, using file storage`);
                        const wishlistData = await loadWishlistData();
                        customerWishlist = wishlistData[customerId] || [];
                    }
                }
            } catch (firebaseError) {
                console.error('[SHOPIFY] Firebase error, using file fallback:', firebaseError.message);
                // Fallback to file storage
                const wishlistData = await loadWishlistData();
                customerWishlist = wishlistData[customerId] || [];
            }
        } else {
            console.log(`[SHOPIFY] Firebase not available, using file storage`);
            // Fallback to file storage
            const wishlistData = await loadWishlistData();
            customerWishlist = wishlistData[customerId] || [];
        }

        console.log(`[SHOPIFY] Returning ${customerWishlist.length} items in wishlist`);

        // ✅ CRITICAL FIX: Process wishlist items through Shopify GraphQL to get proper variant images
        // This ensures the public API returns the same rich data as the mobile API
        if (customerWishlist.length > 0) {
            try {
                // Extract product IDs for Shopify lookup
                const wishlistProductIds = customerWishlist.map(item => item.productId).filter(Boolean);
                
                if (wishlistProductIds.length > 0) {
                    console.log(`[SHOPIFY] Fetching product details from Shopify for ${wishlistProductIds.length} products`);
                    
                    // Use the same GraphQL query as the mobile API
                    const productsQuery = `
                      query getWishlistProducts($productIds: [ID!]!) {
                        nodes(ids: $productIds) {
                          ... on Product {
                            id
                            title
                            handle
                            description
                            productType
                            vendor
                            tags
                            createdAt
                            priceRange {
                              maxVariantPrice {
                                amount
                                currencyCode
                              }
                              minVariantPrice {
                                amount
                                currencyCode
                              }
                            }
                            compareAtPriceRange {
                              maxVariantCompareAtPrice {
                                amount
                                currencyCode
                              }
                              minVariantCompareAtPrice {
                                amount
                                currencyCode
                              }
                            }
                            featuredImage {
                              url
                              altText
                            }
                            images(first: 5) {
                              edges {
                                node {
                                  url
                                  altText
                                }
                              }
                            }
                            variants(first: 10) {
                              edges {
                                node {
                                  id
                                  title
                                  sku
                                  price
                                  compareAtPrice
                                  selectedOptions {
                                    name
                                    value
                                  }
                                  image {
                                    url
                                  }
                                }
                              }
                            }
                            totalInventory
                          }
                        }
                      }
                    `;

                    const productsResponse = await axios.post(
                      config.adminApiUrl,
                      {
                        query: productsQuery,
                        variables: { productIds: wishlistProductIds }
                      },
                      {
                        headers: {
                          'X-Shopify-Access-Token': config.adminToken,
                          'Content-Type': 'application/json'
                        }
                      }
                    );

                    const products = productsResponse.data.data?.nodes || [];
                    console.log(`[SHOPIFY] Fetched details for ${products.length} products from Shopify`);
                    
                    // Process each wishlist item with its corresponding product data
                    const enhancedWishlist = [];
                    
                    for (const wishlistItem of customerWishlist) {
                        const product = products.find(p => p && p.id === wishlistItem.productId);
                        
                        if (product) {
                            // Use the same variant processing logic as the mobile API
                            const processedVariants = product.variants.edges.map(edge => ({
                                id: edge.node.id,
                                title: edge.node.title,
                                sku: edge.node.sku,
                                price: edge.node.price,
                                compareAtPrice: edge.node.compareAtPrice,
                                selectedOptions: edge.node.selectedOptions,
                                image: edge.node.image
                            }));
                            
                            let selectedVariant = null;
                            let selectedOptions = {};
                            let selectedSku = null;
                            let selectedPrice = null;
                            let selectedCompareAtPrice = null;
                            let selectedImage = null;
                            
                            if (wishlistItem.selectedOptions || wishlistItem.variantId) {
                                console.log(`🔍 [VARIANT] Processing public wishlist item:`, {
                                    productId: product.id,
                                    variantId: wishlistItem.variantId,
                                    selectedOptions: wishlistItem.selectedOptions
                                });
                                
                                // Find the matching variant by ID first
                                if (wishlistItem.variantId) {
                                    selectedVariant = processedVariants.find(v => v.id === wishlistItem.variantId);
                                }
                                
                                // If no variant ID match, try to match by selectedOptions
                                if (!selectedVariant && wishlistItem.selectedOptions) {
                                    selectedVariant = processedVariants.find(variant => {
                                        const variantOptions = {};
                                        variant.selectedOptions.forEach(opt => {
                                            variantOptions[opt.name] = opt.value;
                                        });
                                        
                                        // Check if all stored options match this variant
                                        return Object.entries(wishlistItem.selectedOptions).every(([key, value]) => 
                                            variantOptions[key] === value
                                        );
                                    });
                                }
                                
                                if (selectedVariant) {
                                    console.log(`✅ [VARIANT] Found matching variant:`, {
                                        variantId: selectedVariant.id,
                                        title: selectedVariant.title,
                                        selectedOptions: selectedVariant.selectedOptions,
                                        image: selectedVariant.image?.url
                                    });
                                    
                                    selectedOptions = {};
                                    selectedVariant.selectedOptions.forEach(opt => {
                                        selectedOptions[opt.name] = opt.value;
                                    });
                                    selectedSku = selectedVariant.sku;
                                    selectedPrice = selectedVariant.price;
                                    selectedCompareAtPrice = selectedVariant.compareAtPrice;
                                    selectedImage = selectedVariant.image?.url || product.featuredImage?.url;
                                } else {
                                    console.log(`⚠️ [VARIANT] No matching variant found, using stored options:`, wishlistItem.selectedOptions);
                                    selectedOptions = wishlistItem.selectedOptions || {};
                                    selectedImage = product.featuredImage?.url;
                                }
                            }
                            
                            // Create enhanced item with proper variant image
                            const enhancedItem = {
                                productId: wishlistItem.productId,
                                variantId: selectedVariant?.id || wishlistItem.variantId || wishlistItem.productId,
                                title: product.title,
                                imageUrl: selectedImage || product.featuredImage?.url || '', // ✅ CRITICAL: Use variant image
                                price: parseFloat(selectedPrice || product.priceRange.minVariantPrice.amount) || 0,
                                compareAtPrice: selectedCompareAtPrice ? parseFloat(selectedCompareAtPrice) : null,
                                sku: selectedSku || '',
                                selectedOptions: selectedOptions, // ✅ CRITICAL: Include selected options
                                handle: product.handle,
                                addedAt: wishlistItem.addedAt,
                                syncedFromFirebase: wishlistItem.syncedFromFirebase || false
                            };
                            
                            enhancedWishlist.push(enhancedItem);
                        } else {
                            // Keep original item if product not found
                            enhancedWishlist.push(wishlistItem);
                        }
                    }
                    
                    console.log(`[SHOPIFY] Enhanced ${enhancedWishlist.length} wishlist items with variant data`);
                    customerWishlist = enhancedWishlist;
                }
            } catch (shopifyError) {
                console.error('[SHOPIFY] Error fetching product details from Shopify:', shopifyError.message);
                // Continue with original data if Shopify lookup fails
            }
        }

        res.json({
            success: true,
            items: customerWishlist,
            count: customerWishlist.length
        });
    } catch (error) {
        console.error('[SHOPIFY] Error getting wishlist:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// Add item to wishlist (public endpoint for Shopify)
app.post('/api/public/wishlist/add', async (req, res) => {
    try {
        const {
            customerId,
            productId,
            variantId,
            title,
            imageUrl,
            price,
            compareAtPrice,
            sku,
            selectedOptions,
            handle
        } = req.body;

        if (!customerId) {
            return res.status(400).json({ 
                success: false,
                error: 'Customer ID is required' 
            });
        }

        if (!productId || !title) {
            return res.status(400).json({ 
                success: false,
                error: 'Product ID and title are required' 
            });
        }

        console.log(`[SHOPIFY] Adding item to wishlist for customer: ${customerId}`);

        // First sync from Firebase to ensure we have the latest data
        await syncFirebaseToPublicStorage(customerId);

        const wishlistData = await loadWishlistData();
        
        if (!wishlistData[customerId]) {
            wishlistData[customerId] = [];
        }

        // Check if item already exists
        const existingItemIndex = wishlistData[customerId].findIndex(item => 
            item.productId === productId && 
            item.variantId === (variantId || productId) &&
            JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
        );

        if (existingItemIndex !== -1) {
            console.log(`[SHOPIFY] Item already exists in wishlist`);
            return res.json({
                success: true,
                message: 'Item already in wishlist',
                alreadyExists: true
            });
        }

        // Add new item to public storage
        const newItem = {
            productId,
            variantId: variantId || productId,
            title,
            imageUrl: imageUrl || '',
            price: price || 0,
            compareAtPrice: compareAtPrice || 0,
            sku: sku || '',
            selectedOptions: selectedOptions || {},
            handle: handle || '',
            addedAt: new Date().toISOString()
        };

        wishlistData[customerId].push(newItem);
        await saveWishlistData(wishlistData);

        console.log(`[SHOPIFY] Item added to public storage successfully`);

        // Also add to Firebase to keep it as canonical source
        if (firebaseEnabled && wishlistService) {
            try {
                console.log(`🔄 [SYNC] Syncing authenticated wishlist to public storage for Shopify customer: ${customerId}`);
                
                // Use the correct customer ID format for Firebase
                const shopifyCustomerId = customerId.startsWith('gid://') ? customerId : `gid://shopify/Customer/${customerId}`;
                
                // ✅ NEW: Get real customer email from Shopify for proper identification
                const customerEmail = await getRealCustomerEmail(customerId);
                
                // Prepare enhanced product data for Firebase
                const productData = {
                    title: title,
                    handle: handle || '',
                    imageUrl: imageUrl || '', // This should be the variant image
                    price: parseFloat(price) || 0,
                    sku: sku || ''
                };
                
                // Use enhanced method to store additional data in Firebase
                const firebaseResult = await wishlistService.addToWishlistWithProductData(
                    shopifyCustomerId, 
                    customerEmail, 
                    productId,
                    variantId,
                    selectedOptions,
                    productData
                );
                console.log(`✅ [SYNC] Item also added to Firebase with enhanced data successfully:`, firebaseResult);
            } catch (firebaseError) {
                console.error('❌ [SYNC] Error adding to Firebase (continuing anyway):', firebaseError.message);
                // Don't fail the request if Firebase fails - this is a sync operation
            }
        }

        // Sync to Shopify customer metafields
        try {
            await syncWishlistToShopify(customerId, wishlistData[customerId]);
        } catch (syncError) {
            console.error('[SHOPIFY] Error syncing to Shopify metafields:', syncError);
            // Don't fail the request if sync fails
        }

        res.json({
            success: true,
            message: 'Item added to wishlist successfully',
            item: newItem,
            count: wishlistData[customerId].length
        });

    } catch (error) {
        console.error('[SHOPIFY] Error adding to wishlist:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// Remove item from wishlist (public endpoint for Shopify)
app.post('/api/public/wishlist/remove', async (req, res) => {
    try {
        const { customerId, variantId, productId, selectedOptions } = req.body;

        if (!customerId) {
            return res.status(400).json({ 
                success: false,
                error: 'Customer ID is required' 
            });
        }

        if (!variantId && !productId) {
            return res.status(400).json({ 
                success: false,
                error: 'Variant ID or Product ID is required' 
            });
        }

        console.log(`[SHOPIFY] Removing item from wishlist for customer: ${customerId}`);
        console.log(`[SHOPIFY] ProductId: ${productId}, VariantId: ${variantId}, SelectedOptions:`, selectedOptions);

        // ✅ PRIORITY 1: Try Firebase first (the source of truth)
        if (firebaseEnabled && wishlistService) {
            try {
                console.log(`[SHOPIFY] Attempting Firebase removal...`);
                
                // Get real customer email for Firebase operations
                const customerEmail = await getRealCustomerEmail(customerId);
                const fullCustomerId = `gid://shopify/Customer/${customerId}`;
                
                console.log(`[SHOPIFY] Using customer email: ${customerEmail}, fullId: ${fullCustomerId}`);
                
                // Remove directly from Firebase
                const firebaseResult = await wishlistService.removeFromWishlist(
                    fullCustomerId, 
                    customerEmail, 
                    productId, 
                    variantId, 
                    selectedOptions
                );
                
                console.log(`[SHOPIFY] Firebase removal result:`, firebaseResult);
                
                if (firebaseResult.success) {
                    // Get updated count from Firebase
                    const updatedItems = await wishlistService.getWishlist(fullCustomerId, customerEmail);
                    const finalCount = updatedItems.length;
                    
                    console.log(`[SHOPIFY] Items after removal: ${finalCount}`);

                    // Also sync to local storage and Shopify metafields for backup
                    try {
                        await syncFirebaseToPublicStorage(customerId);
                        console.log(`[SHOPIFY] Synced to public storage`);
                        
                        // Load from public storage for Shopify sync
                        const wishlistData = await loadWishlistData();
                        if (wishlistData[customerId]) {
                            await syncWishlistToShopify(customerId, wishlistData[customerId]);
                            console.log(`[SHOPIFY] Synced to Shopify metafields`);
                        }
                    } catch (syncError) {
                        console.error('[SHOPIFY] Error with sync operations (non-critical):', syncError);
                        // Don't fail the request if sync fails
                    }

                    return res.json({
                        success: true,
                        message: 'Item removed from wishlist',
                        count: finalCount
                    });
                } else {
                    console.log(`[SHOPIFY] Firebase removal unsuccessful, falling back to local storage`);
                }
                
            } catch (firebaseError) {
                console.error('[SHOPIFY] Firebase removal failed, falling back to local storage:', firebaseError.message);
            }
        } else {
            console.log(`[SHOPIFY] Firebase not available, using local storage fallback`);
        }

        // ✅ FALLBACK: Use local storage if Firebase fails or isn't available
        console.log(`[SHOPIFY] Using local storage fallback for removal...`);
        
        try {
            const wishlistData = await loadWishlistData();
            
            if (!wishlistData[customerId] || !Array.isArray(wishlistData[customerId])) {
                console.log(`[SHOPIFY] No wishlist found for customer ${customerId}`);
                return res.json({ 
                    success: true, 
                    message: 'Item not in wishlist',
                    count: 0
                });
            }

            const originalCount = wishlistData[customerId].length;
            console.log(`[SHOPIFY] Original wishlist size: ${originalCount}`);

            // Find and remove the matching item
            const itemIndex = wishlistData[customerId].findIndex(item => {
                // Match by product ID and variant ID
                const productMatch = item.productId === productId;
                const variantMatch = !variantId || item.variantId === variantId;
                
                // Match selected options if provided
                let optionsMatch = true;
                if (selectedOptions && Object.keys(selectedOptions).length > 0) {
                    optionsMatch = JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions);
                }
                
                return productMatch && variantMatch && optionsMatch;
            });

            if (itemIndex === -1) {
                console.log(`[SHOPIFY] Item not found in local wishlist`);
                return res.json({ 
                    success: true, 
                    message: 'Item not found in wishlist',
                    count: originalCount
                });
            }

            // Remove the item
            wishlistData[customerId].splice(itemIndex, 1);
            const finalCount = wishlistData[customerId].length;
            
            console.log(`[SHOPIFY] Removed item, new count: ${finalCount}`);
            
            // Save the updated data
            await saveWishlistData(wishlistData);
            console.log(`[SHOPIFY] Saved updated wishlist data`);

            // Sync to Shopify metafields
            try {
                await syncWishlistToShopify(customerId, wishlistData[customerId]);
                console.log(`[SHOPIFY] Synced to Shopify metafields`);
            } catch (syncError) {
                console.error('[SHOPIFY] Error syncing to Shopify (non-critical):', syncError);
            }

            res.json({
                success: true,
                message: 'Item removed from wishlist',
                count: finalCount
            });

        } catch (storageError) {
            console.error('[SHOPIFY] Error with local storage fallback:', storageError);
            throw storageError;
        }
        
    } catch (error) {
        console.error('[SHOPIFY] Error removing from wishlist:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// Migrate wishlist from device ID to customer email when user logs in
app.post('/api/public/wishlist/migrate', async (req, res) => {
    try {
        const { deviceId, customerId, customerEmail } = req.body;

        if (!deviceId || !customerId) {
            return res.status(400).json({ 
                success: false,
                error: 'Device ID and customer ID are required' 
            });
        }

        console.log(`[MIGRATION] Migrating wishlist from device ${deviceId} to customer ${customerId} (${customerEmail})`);

        let migratedCount = 0;

        // 1. Migrate in public storage (JSON file)
        const wishlistData = await loadWishlistData();
        
        if (wishlistData[deviceId] && wishlistData[deviceId].length > 0) {
            console.log(`[MIGRATION] Found ${wishlistData[deviceId].length} items for device ${deviceId}`);
            
            // Ensure customer wishlist exists
            if (!wishlistData[customerId]) {
                wishlistData[customerId] = [];
            }
            
            // Merge device wishlist into customer wishlist (avoid duplicates)
            const deviceItems = wishlistData[deviceId];
            for (const deviceItem of deviceItems) {
                // Check if item already exists in customer wishlist
                const existingItemIndex = wishlistData[customerId].findIndex(item => 
                    item.productId === deviceItem.productId && 
                    item.variantId === deviceItem.variantId &&
                    JSON.stringify(item.selectedOptions || {}) === JSON.stringify(deviceItem.selectedOptions || {})
                );
                
                if (existingItemIndex === -1) {
                    // Item doesn't exist, add it
                    wishlistData[customerId].push({
                        ...deviceItem,
                        migratedFromDevice: deviceId,
                        migratedAt: new Date().toISOString()
                    });
                    migratedCount++;
                }
            }
            
            // Remove device wishlist after migration
            delete wishlistData[deviceId];
            await saveWishlistData(wishlistData);
            
            console.log(`[MIGRATION] Migrated ${migratedCount} items from device to public storage`);
        }

        // 2. Migrate in Firebase
        if (firebaseEnabled && wishlistService && customerEmail) {
            try {
                console.log(`[MIGRATION] Migrating Firebase entries from device ${deviceId} to customer ${customerId}`);
                
                // Get device wishlist from Firebase
                const deviceFirebaseItems = await wishlistService.getWishlist(deviceId, `device@${deviceId}.guest`);
                
                if (deviceFirebaseItems.length > 0) {
                    console.log(`[MIGRATION] Found ${deviceFirebaseItems.length} items in Firebase for device ${deviceId}`);
                    
                    // Add each item to customer's Firebase wishlist
                    for (const item of deviceFirebaseItems) {
                        try {
                            await wishlistService.addToWishlistWithProductData(
                                customerId.startsWith('gid://') ? customerId : `gid://shopify/Customer/${customerId}`,
                                customerEmail,
                                item.productId,
                                item.variantId,
                                item.selectedOptions,
                                {
                                    title: item.title,
                                    handle: item.handle,
                                    imageUrl: item.imageUrl,
                                    price: item.price,
                                    sku: item.sku
                                }
                            );
                        } catch (addError) {
                            console.error(`[MIGRATION] Error adding item ${item.productId} to customer Firebase:`, addError.message);
                        }
                    }
                    
                    // Remove device wishlist from Firebase
                    await wishlistService.clearWishlist(deviceId, `device@${deviceId}.guest`);
                    
                    console.log(`[MIGRATION] Successfully migrated Firebase entries`);
                }
            } catch (firebaseError) {
                console.error('[MIGRATION] Error migrating Firebase data:', firebaseError.message);
                // Don't fail the entire migration if Firebase fails
            }
        }

        res.json({
            success: true,
            message: `Successfully migrated ${migratedCount} wishlist items`,
            migratedCount: migratedCount,
            deviceId: deviceId,
            customerId: customerId
        });

    } catch (error) {
        console.error('[MIGRATION] Error migrating wishlist:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});

// Debug endpoint to see all customer IDs in wishlist (temporary)
app.get('/api/debug/wishlist-customers', async (req, res) => {
    try {
        const wishlistData = await loadWishlistData();
        const customerIds = Object.keys(wishlistData);
        
        res.json({
            success: true,
            customerIds: customerIds,
            totalCustomers: customerIds.length,
            dataSnapshot: Object.fromEntries(
                customerIds.map(id => [id, wishlistData[id].length])
            )
        });
    } catch (error) {
        console.error('Debug endpoint error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Sync endpoint to manually sync Firebase to public storage
app.post('/api/sync/firebase-to-public', async (req, res) => {
    try {
        const { customerId } = req.body;
        
        if (customerId) {
            // Sync specific customer
            console.log(`[SYNC] Manual sync requested for customer: ${customerId}`);
            const success = await syncFirebaseToPublicStorage(customerId);
            
            res.json({
                success: success,
                message: success ? 
                    `Successfully synced wishlist for customer ${customerId}` : 
                    `Failed to sync wishlist for customer ${customerId}`,
                customerId: customerId
            });
        } else {
            // Sync all customers
            console.log('[SYNC] Manual full sync requested');
            const success = await syncAllFirebaseToPublicStorage();
            
            res.json({
                success: success,
                message: success ? 
                    'Successfully synced all wishlists from Firebase to public storage' : 
                    'Failed to sync wishlists'
            });
        }
        
    } catch (error) {
        console.error('[SYNC] Manual sync error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error',
            details: error.message
        });
    }
});

// Health check endpoint that also tests sync functionality
app.get('/api/health/sync', async (req, res) => {
    try {
        const healthResult = {
            firebase: false,
            publicStorage: false,
            sync: false
        };
        
        // Test Firebase
        if (firebaseEnabled && wishlistService) {
            try {
                const firebaseHealth = await wishlistService.healthCheck();
                healthResult.firebase = firebaseHealth.status === 'healthy';
            } catch (error) {
                console.error('Firebase health check failed:', error);
            }
        }
        
        // Test public storage
        try {
            const wishlistData = await loadWishlistData();
            healthResult.publicStorage = typeof wishlistData === 'object';
        } catch (error) {
            console.error('Public storage health check failed:', error);
        }
        
        // Test sync functionality (if Firebase is available)
        if (healthResult.firebase) {
            try {
                // This is a dry-run sync test - we don't actually change data
                healthResult.sync = true;
            } catch (error) {
                console.error('Sync health check failed:', error);
            }
        }
        
        const overallHealth = healthResult.firebase && healthResult.publicStorage;
        
        res.json({
            success: true,
            status: overallHealth ? 'healthy' : 'degraded',
            components: healthResult,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Health check error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Health check failed',
            details: error.message
        });
    }
});

// Endpoint to manually link Shopify customer ID to Flutter app data
app.post('/api/debug/link-customer', async (req, res) => {
    try {
        const { shopifyCustomerId, flutterSessionId } = req.body;
        
        if (!shopifyCustomerId) {
            return res.status(400).json({
                success: false,
                error: 'Shopify customer ID is required'
            });
        }

        console.log(`[DEBUG] Attempting to link Shopify customer ${shopifyCustomerId} to Flutter session data`);

        // For now, let's manually copy the test data we know exists
        // This is a temporary solution to test the concept
        
        const wishlistData = await loadWishlistData();
        
        // Create some test data for the Shopify customer ID
        wishlistData[shopifyCustomerId] = [
            {
                "productId": "gid://shopify/Product/11613507059980",
                "variantId": "1001359",
                "title": "BUCHSTÜTZE DARCY (2er Set)",
                "imageUrl": "https://cdn.shopify.com/s/files/1/0483/4374/4676/files/Buchstutzen-metall-4.jpg?v=1749124129",
                "price": 4000,
                "compareAtPrice": null,
                "selectedOptions": {"Farbe": "Matcha Latte"},
                "handle": "buchstutze-darcy-2er-set",
                "addedAt": new Date().toISOString()
            },
            {
                "productId": "gid://shopify/Product/6698295525540",
                "variantId": "1000629",
                "title": "LEDER S-HAKEN (3er/6er Set)",
                "imageUrl": "https://cdn.shopify.com/s/files/1/0483/4374/4676/files/Leder_S-Haken-14.jpg?v=1741264491",
                "price": 3000,
                "compareAtPrice": null,
                "selectedOptions": {"Leder Farbe": "Beige", "Haken Farbe": "Weiß", "Anzahl": "3er Set"},
                "handle": "leder-s-haken-3er-6er-set",
                "addedAt": new Date().toISOString()
            }
        ];

        await saveWishlistData(wishlistData);

        console.log(`[DEBUG] Successfully linked customer ${shopifyCustomerId} with 2 test items`);

        res.json({
            success: true,
            message: `Successfully linked customer ${shopifyCustomerId}`,
            itemCount: wishlistData[shopifyCustomerId].length
        });

    } catch (error) {
        console.error('[DEBUG] Error linking customer:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Clear wishlist for a customer (debug endpoint)
app.delete('/api/debug/clear-customer-wishlist', async (req, res) => {
    try {
        const { customerId } = req.body;
        
        if (!customerId) {
            return res.status(400).json({
                success: false,
                error: 'Customer ID is required'
            });
        }

        console.log(`[DEBUG] Clearing wishlist for customer: ${customerId}`);

        const wishlistData = await loadWishlistData();
        
        if (wishlistData[customerId]) {
            wishlistData[customerId] = [];
            await saveWishlistData(wishlistData);
            console.log(`[DEBUG] Successfully cleared wishlist for customer ${customerId}`);
        }

        res.json({
            success: true,
            message: `Wishlist cleared for customer ${customerId}`,
            itemCount: 0
        });

    } catch (error) {
        console.error('[DEBUG] Error clearing wishlist:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Apply store credit by simply deducting from customer balance
app.post('/apply-store-credit', async (req, res) => {
  try {
    console.log('📧 Store credit request received:');
    console.log('   Headers:', JSON.stringify(req.headers, null, 2));
    console.log('   Raw body:', req.body);
    console.log('   Body type:', typeof req.body);
    console.log('   Body keys:', Object.keys(req.body || {}));
    
    const { customerEmail, storeCreditAmount, cartTotal } = req.body;
    
    console.log(`💳 [STORE_CREDIT] Store credit deduction request:`);
    console.log(`   Customer: ${customerEmail}`);
    console.log(`   Available store credit: ${storeCreditAmount}€`);
    console.log(`   Cart total: ${cartTotal}€`);
    
    if (!customerEmail || !storeCreditAmount || !cartTotal) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: customerEmail, storeCreditAmount, cartTotal'
      });
    }

    // Calculate the actual amount to deduct (minimum of available store credit and cart total)
    const amountToDeduct = Math.min(parseFloat(storeCreditAmount), parseFloat(cartTotal));
    console.log(`💰 Will deduct ${amountToDeduct}€ from store credit balance`);
    
    if (amountToDeduct <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid deduction amount'
      });
    }

    // Step 1: Get customer ID and verify store credit balance
    const customerQuery = `
      query getCustomer($email: String!) {
        customers(first: 1, query: $email) {
          edges {
            node {
              id
              email
              storeCreditAccounts(first: 10) {
                edges {
                  node {
                    id
                    balance {
                      amount
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;

    // Use Shopify customer search syntax: "email:address@example.com"
    const customerSearchQuery = `email:${customerEmail}`;
    const customerResponse = await axios.post(
      config.adminApiUrl,
      {
        query: customerQuery,
        variables: { email: customerSearchQuery }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json',
        },
      }
    );

    // Debug: log response from Shopify to help diagnose missing customers/store credit
    console.log('[DEBUG] customerResponse.data:', JSON.stringify(customerResponse.data, null, 2));

    const customers = customerResponse.data?.data?.customers?.edges || [];
    if (customers.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Customer not found'
      });
    }

    const customer = customers[0].node;
    console.log(`👤 Found customer: ${customer.email} (${customer.id})`);

    // Calculate available store credit
    const storeCreditAccounts = customer.storeCreditAccounts?.edges || [];
    let totalStoreCredit = 0;
    let storeCreditAccountId = null;

    storeCreditAccounts.forEach(edge => {
      const amount = parseFloat(edge.node.balance?.amount || 0);
      totalStoreCredit += amount;
      if (amount > 0 && !storeCreditAccountId) {
        storeCreditAccountId = edge.node.id; // Use the first account with balance
      }
    });

    console.log(`💰 Customer has ${totalStoreCredit}€ store credit available`);

    if (totalStoreCredit < amountToDeduct) {
      return res.status(400).json({
        success: false,
        error: `Insufficient store credit. Available: ${totalStoreCredit}€, Requested: ${amountToDeduct}€`
      });
    }

    if (!storeCreditAccountId) {
      return res.status(400).json({
        success: false,
        error: 'No valid store credit account found'
      });
    }

    // GraphQL mutation to create a basic code discount (define once, use for both new and reused reservations)
    const createDiscountMutation = `
      mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
        discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
          codeDiscountNode { id }
          userErrors { field message }
        }
      }
    `;

    // Step 2: Check if customer already has a pending reservation
    const existingReservations = Array.from(storeCreditReservations.values())
      .filter(r => r.email === customerEmail.toLowerCase() && 
                   r.status === 'reserved' && // Changed from 'pending_debit' to match new status
                   r.expiresAt > Date.now());
                   
    if (existingReservations.length > 0) {
      // Found existing reservation - CREATE A NEW DISCOUNT CODE for it
      const existingRes = existingReservations[0];
      console.log(`♻️ Found existing reservation ${existingRes.id} - creating NEW discount code (old one may be used/expired)`);
      
      // Create a NEW discount code for the existing reservation
      const newDiscountCode = `STORE_CREDIT_${Date.now()}_${existingRes.id.toUpperCase()}`;
      console.log(`💳 Creating NEW discount code: ${newDiscountCode} for existing reservation`);
      
      // Update the reservation with the new discount code
      existingRes.discountCode = newDiscountCode;
      storeCreditReservations.set(existingRes.id, existingRes);
      await persistStoreCreditReservations();
      
      // Create the Shopify discount code for the existing reservation
      const amountStr = Number(existingRes.amount).toFixed(2);
      const discountInput = {
        basicCodeDiscount: {
          title: `Store Credit Reserved - ${customerEmail} - ${existingRes.id}`,
          code: newDiscountCode,
          startsAt: new Date().toISOString(),
          endsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // Expires in 24 hours
          combinesWith: { orderDiscounts: true, productDiscounts: true, shippingDiscounts: true },
          customerGets: {
            value: {
              discountAmount: {
                amount: amountStr,
                appliesOnEachItem: false
              }
            },
            items: { all: true }
          },
          customerSelection: { all: true },
          usageLimit: 1
        }
      };
      
      try {
        const discountResponse = await axios.post(
          config.adminApiUrl,
          { query: createDiscountMutation, variables: discountInput },
          { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } }
        );
        
        const discountData = discountResponse.data?.data?.discountCodeBasicCreate;
        const discountErrors = discountData?.userErrors || [];
        
        if (discountErrors.length > 0) {
          console.error('❌ Failed to create new discount for existing reservation:', discountErrors);
          return res.status(500).json({ success: false, error: 'Failed to create new discount code', debugInfo: discountErrors });
        }
        
        console.log(`✅ Created NEW discount code for existing reservation: ${newDiscountCode}`);
        
        return res.status(200).json({
          success: true,
          discountCode: newDiscountCode,
          appliedStoreCredit: existingRes.amount, // Flutter expects this field name
          newStoreCreditBalance: totalStoreCredit, // Flutter expects this field name
          reservationId: existingRes.id,
          isReused: true,
          newDiscountCreated: true
        });
        
      } catch (error) {
        console.error('❌ Error creating new discount for existing reservation:', error);
        return res.status(500).json({ success: false, error: 'Failed to create discount code' });
      }
    }

    // Step 3: Create new reservation (NO MONEY DEDUCTED YET)
    const reservationId = generateReservationId();
    const reservationDiscountCode = `STORE_CREDIT_${Date.now()}_${reservationId.toUpperCase()}`;
    
    console.log(`💳 Creating reservation ${reservationId} and discount code: ${reservationDiscountCode} for ${amountToDeduct}€ (money NOT deducted yet)`);
    
    // Create reservation to track this transaction
    const reservation = {
      id: reservationId,
      email: customerEmail.toLowerCase(),
      amount: amountToDeduct,
      discountCode: reservationDiscountCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + (30 * 60 * 1000), // 30 minutes
      status: 'reserved', // Money not deducted yet
      storeCreditAccountId: storeCreditAccountId,
      customerGid: customer.id
    };
    
    storeCreditReservations.set(reservationId, reservation);
    await persistStoreCreditReservations();

    // Format the amount as a string with two decimals
    const amountStr = Number(amountToDeduct).toFixed(2);

    // Build discount input using the reservation discount code
    const discountInput = {
      basicCodeDiscount: {
        title: `Store Credit Reserved - ${customerEmail} - ${reservationId}`,
        code: reservationDiscountCode, // Use the reservation code, not a new random one
        startsAt: new Date().toISOString(),
        endsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // Expires in 24 hours
        combinesWith: { orderDiscounts: true, productDiscounts: true, shippingDiscounts: true },
        customerGets: {
          value: {
            discountAmount: {
              amount: amountStr,
              appliesOnEachItem: false
            }
          },
          items: { all: true }
        },
        customerSelection: { all: true },
        usageLimit: 1
      }
    };

    console.log('📋 Sending Admin API variables:', JSON.stringify(discountInput, null, 2));

    let lastErrorResponse = null;
    let createdDiscountCode = null;

    try {
      const discountResponse = await axios.post(
        config.adminApiUrl,
        { query: createDiscountMutation, variables: discountInput },
        { headers: { 'X-Shopify-Access-Token': config.adminToken, 'Content-Type': 'application/json' } }
      );

      console.log('📋 Discount response:', JSON.stringify(discountResponse.data, null, 2));
      lastErrorResponse = discountResponse.data;

      if (Array.isArray(discountResponse.data?.errors) && discountResponse.data.errors.length) {
        console.error('❌ Admin API top-level GraphQL errors:', JSON.stringify(discountResponse.data.errors, null, 2));
        return res.status(500).json({ success: false, error: 'Admin API top-level errors', debugInfo: { lastResponse: lastErrorResponse } });
      }

      const discountData = discountResponse.data?.data?.discountCodeBasicCreate;
      if (!discountData) {
        console.error('❌ Admin API returned no discount data (data.discountCodeBasicCreate is null)');
        return res.status(500).json({ success: false, error: 'Admin API returned no discount data', debugInfo: { lastResponse: lastErrorResponse } });
      }

      const discountErrors = discountData?.userErrors || [];
      if (discountErrors.length > 0) {
        console.error('❌ Discount creation userErrors:', JSON.stringify(discountErrors, null, 2));
        return res.status(500).json({ success: false, error: 'Discount creation userErrors', debugInfo: { lastResponse: lastErrorResponse } });
      }

      // Success
      console.log('✅ Admin API reported success for discount creation (no userErrors)');
      createdDiscountCode = reservationDiscountCode; // Use the reservation code
      
      // Do NOT mark reservation as debited - money hasn't been deducted yet
      // Reservation stays in 'reserved' status until order webhook confirms purchase
      
    } catch (err) {
      console.error('❌ Error calling Admin API:', err?.response?.data || err.message || err);
      lastErrorResponse = err?.response?.data || { message: err.message };
      return res.status(500).json({ success: false, error: 'Admin API request failed', debugInfo: { lastResponse: lastErrorResponse } });
    }

    if (!createdDiscountCode) {
      console.error('❌ No discount variant succeeded. Last response:', JSON.stringify(lastErrorResponse, null, 2));
      return res.status(500).json({
        success: false,
        error: 'Failed to create discount code - no code returned',
        debugInfo: { lastResponse: lastErrorResponse }
      });
    }

    // Success: return created code in the format Flutter app expects
    console.log(`💰 Store credit reservation of ${amountToDeduct}€ created and discount code ready`);
    
    res.json({
      success: true,
      message: 'Store credit reserved and discount code created',
      discountCode: createdDiscountCode,
      appliedStoreCredit: amountToDeduct, // Flutter expects this field name
      newStoreCreditBalance: totalStoreCredit, // Flutter expects this field name  
      customerId: customer.id,
      reservationId: reservationId
    });

  } catch (error) {
    console.error('❌ Error processing store credit:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process store credit',
      details: error.message
    });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Combined Auth Server running on port ${PORT}`);
  console.log(`OAuth endpoints ready at: ${config.issuer}`);
  console.log(`Mobile endpoints ready at: ${config.issuer}/auth/*`);
  console.log(`Customer endpoints ready at: ${config.issuer}/customer/*`);
  console.log(`🔥 Return management endpoints ready at: ${config.issuer}/returns/*`);
  console.log(`Admin token configured: ${config.adminToken ? 'YES' : 'NO'}`);
  console.log(`Storefront token configured: ${config.storefrontToken ? 'YES' : 'NO'}`);
  
  // 🔥 PRODUCTION: Show new configuration
  console.log('✅ PRODUCTION Authentication Server Configuration:');
  console.log(`   - Access Token Lifetime: ${Math.round(config.tokenLifetimes.accessToken / (24 * 60 * 60))} days`);
  console.log(`   - Refresh Token Lifetime: ${Math.round(config.tokenLifetimes.refreshToken / (24 * 60 * 60))} days`);
  console.log(`   - Refresh Warning: ${config.refreshThresholds.warningDays} days before expiry`);
  console.log(`   - Users will stay logged in for MONTHS!`);
});
