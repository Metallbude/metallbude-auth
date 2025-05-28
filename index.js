require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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
  adminToken: process.env.SHOPIFY_ADMIN_TOKEN, // Add admin token
  apiUrl: process.env.SHOPIFY_API_URL || 'https://metallbude-de.myshopify.com/api/2024-10/graphql.json',
  adminApiUrl: process.env.SHOPIFY_ADMIN_API_URL || 'https://metallbude-de.myshopify.com/admin/api/2024-10/graphql.json',
  mailerSendApiKey: process.env.MAILERSEND_API_KEY,
  privateKey,
  publicKey,
  clients: {
    'shopify_client_id': {
      client_secret: process.env.SHOPIFY_CLIENT_SECRET || 'b079a4c59a9b24f43971a95abaa6b0e2c384b597275d477b1ee8444e26db81ec',
      redirect_uris: [
        'https://account.metallbude.com/authentication/login/external/callback',
        'https://shopify.com/authentication/48343744676/login/external/callback',
        'https://metallbude-de.myshopify.com/account/auth/callback',
        'https://metallbude-de.myshopify.com/account/connect/callback'
      ]
    }
  },
  // Storage
  verificationCodes: new Map(),
  authorizationCodes: new Map(),
  accessTokens: new Map(),
  refreshTokens: new Map(),
  sessions: new Map(),
  customerEmails: new Map() // Store email -> customer ID mapping
};

// Helper functions
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
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
    // Make email search case-insensitive
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
          query: `email:"${email}"` // Exact email search with quotes
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
    
    // Find exact match (case-insensitive)
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

  // Check if customer exists in Shopify using Admin API
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
  const { email, code, sessionId } = req.body;

  const verificationData = config.verificationCodes.get(sessionId);
  
  if (!verificationData || 
      verificationData.code !== code || 
      verificationData.email !== email ||
      verificationData.expiresAt < Date.now()) {
    return res.status(400).json({ success: false, error: 'Ungültiger oder abgelaufener Code' });
  }

  let customerId;
  let customerData;
  
  // Try to get real customer data from Shopify
  let shopifyCustomer = await getShopifyCustomerByEmail(email);
  
  if (!shopifyCustomer && verificationData.isNewCustomer) {
    // Create new customer in Shopify
    shopifyCustomer = await createShopifyCustomer(email);
  }
  
  if (shopifyCustomer) {
    // Use real Shopify customer data
    customerId = shopifyCustomer.id;
    customerData = {
      id: shopifyCustomer.id,
      email: shopifyCustomer.email,
      displayName: shopifyCustomer.displayName || shopifyCustomer.email.split('@')[0],
      firstName: shopifyCustomer.firstName || '',
      lastName: shopifyCustomer.lastName || ''
    };
  } else {
    // Fallback to generated data if Shopify API fails
    customerId = config.customerEmails.get(email) || 
                 `gid://shopify/Customer/${crypto.randomBytes(8).toString('hex')}`;
    customerData = {
      id: customerId,
      email: email,
      displayName: email.split('@')[0]
    };
    config.customerEmails.set(email, customerId);
  }

  // Generate access token for the app
  const accessToken = crypto.randomBytes(32).toString('hex');
  config.sessions.set(accessToken, {
    email,
    customerId,
    customerData,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
  });

  config.verificationCodes.delete(sessionId);

  res.json({
    success: true,
    accessToken,
    customer: customerData
  });
});

// ===== CUSTOMER DATA ENDPOINTS FOR FLUTTER APP =====

// Middleware to authenticate app tokens
const authenticateAppToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);
  let session = config.sessions.get(token);
  
  // Temporary: If session not found, create one for existing tokens
  // Remove this after all users have logged in again
  if (!session && token.length === 64) {
    console.log('Creating temporary session for existing token');
    // For now, we don't know the email, so return a basic response
    session = {
      email: 'unknown@example.com',
      customerId: 'gid://shopify/Customer/temporary',
      customerData: {
        id: 'gid://shopify/Customer/temporary',
        email: 'unknown@example.com',
        displayName: 'User'
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    };
    // Don't store this temporary session
  }
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Check if session is expired
  if (session.expiresAt && session.expiresAt < Date.now()) {
    config.sessions.delete(token);
    return res.status(401).json({ error: 'Token expired' });
  }

  req.session = session;
  next();
};

// GET /auth/validate - Validate app token
app.get('/auth/validate', authenticateAppToken, (req, res) => {
  res.json({
    valid: true,
    customer: req.session.customerData
  });
});

// GET /customer/profile - Get customer profile
app.get('/customer/profile', authenticateAppToken, async (req, res) => {
  try {
    // Try to get fresh data from Shopify
    const shopifyCustomer = await getShopifyCustomerByEmail(req.session.email);
    
    if (shopifyCustomer) {
      const customer = {
        id: shopifyCustomer.id,
        email: shopifyCustomer.email,
        firstName: shopifyCustomer.firstName || '',
        lastName: shopifyCustomer.lastName || '',
        displayName: shopifyCustomer.displayName || shopifyCustomer.email.split('@')[0],
        phone: shopifyCustomer.phone || null,
        acceptsMarketing: shopifyCustomer.emailMarketingConsent?.marketingState === 'SUBSCRIBED',
        defaultAddress: shopifyCustomer.defaultAddress || null
      };
      res.json({ customer });
    } else {
      // Fallback to session data
      const customer = {
        ...req.session.customerData,
        firstName: req.session.customerData.firstName || req.session.customerData.displayName,
        lastName: req.session.customerData.lastName || '',
        phone: null,
        acceptsMarketing: false,
        defaultAddress: null
      };
      res.json({ customer });
    }
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// GET /customer/orders - Get customer orders
app.get('/customer/orders', authenticateAppToken, async (req, res) => {
  try {
    if (!config.adminToken) {
      return res.json({ orders: [] });
    }

    console.log('Fetching orders for customer:', req.session.customerId);
    console.log('Session data:', JSON.stringify(req.session));

    // Get orders from Shopify Admin API
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
                displayFulfillmentStatus
                displayFinancialStatus
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
    `;

    const response = await axios.post(
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
        }
      }
    );

    console.log('Orders response:', JSON.stringify(response.data).substring(0, 200));

    if (response.data.errors) {
      console.error('GraphQL errors:', response.data.errors);
      return res.json({ orders: [] });
    }

    const orderEdges = response.data?.data?.customer?.orders?.edges || [];
    console.log(`Found ${orderEdges.length} orders`);
    
    // Transform orders to match the expected format
    const orders = orderEdges.map(edge => {
      const order = edge.node;
      return {
        id: order.id,
        name: order.name,
        orderNumber: parseInt(order.name.replace('#', '')) || 0,
        processedAt: order.processedAt,
        fulfillmentStatus: order.displayFulfillmentStatus,
        financialStatus: order.displayFinancialStatus,
        currentTotalPrice: {
          amount: order.currentTotalPriceSet.shopMoney.amount,
          currencyCode: order.currentTotalPriceSet.shopMoney.currencyCode
        },
        totalPriceV2: {
          amount: order.currentTotalPriceSet.shopMoney.amount,
          currencyCode: order.currentTotalPriceSet.shopMoney.currencyCode
        },
        totalRefundedV2: order.totalRefundedSet ? {
          amount: order.totalRefundedSet.shopMoney.amount,
          currencyCode: order.totalRefundedSet.shopMoney.currencyCode
        } : null,
        subtotalPriceV2: {
          amount: order.currentSubtotalPriceSet.shopMoney.amount,
          currencyCode: order.currentSubtotalPriceSet.shopMoney.currencyCode
        },
        totalShippingPriceV2: {
          amount: order.totalShippingPriceSet.shopMoney.amount,
          currencyCode: order.totalShippingPriceSet.shopMoney.currencyCode
        },
        totalTaxV2: order.currentTotalTaxSet ? {
          amount: order.currentTotalTaxSet.shopMoney.amount,
          currencyCode: order.currentTotalTaxSet.shopMoney.currencyCode
        } : null,
        shippingAddress: order.shippingAddress,
        lineItems: {
          edges: order.lineItems.edges.map(item => ({
            node: {
              ...item.node,
              originalTotalPrice: item.node.originalUnitPriceSet ? {
                amount: (parseFloat(item.node.originalUnitPriceSet.shopMoney.amount) * item.node.quantity).toString(),
                currencyCode: item.node.originalUnitPriceSet.shopMoney.currencyCode
              } : null
            }
          }))
        }
      };
    });

    res.json({ orders });
  } catch (error) {
    console.error('Orders fetch error:', error.response?.data || error.message);
    res.json({ orders: [] });
  }
});

// GET /customer/store-credit - Get store credit
app.get('/customer/store-credit', authenticateAppToken, async (req, res) => {
  try {
    if (!config.adminToken) {
      return res.json({ amount: 0.0, currency: 'EUR' });
    }

    console.log('Fetching store credit for customer:', req.session.customerId);

    // Query customer with store credit balance
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

    const response = await axios.post(
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
        }
      }
    );

    console.log('Store credit response:', JSON.stringify(response.data));

    if (response.data.errors) {
      console.error('GraphQL errors:', response.data.errors);
      
      // Fallback to metafield approach for older Shopify setups
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
          }
        }
      );
      
      const metafield = metafieldResponse.data?.data?.customer?.metafield;
      const creditAmount = metafield?.value ? parseFloat(metafield.value) : 0.0;
      
      return res.json({
        amount: creditAmount,
        currency: 'EUR'
      });
    }

    // Calculate total store credit from all accounts
    let totalCredit = 0.0;
    const storeCreditAccounts = response.data?.data?.customer?.storeCreditAccounts?.edges || [];
    
    storeCreditAccounts.forEach(edge => {
      if (edge.node?.balance?.amount) {
        totalCredit += parseFloat(edge.node.balance.amount);
      }
    });
    
    console.log('Total store credit:', totalCredit);

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

// This is what your backend endpoint should look like (Node.js/Express example)

app.put('/customer/update', authenticateToken, async (req, res) => {
  try {
    const { updates } = req.body;
    const customerId = req.user.customerId; // From JWT token
    
    // Build the mutation dynamically based on what fields are being updated
    let mutationFields = [];
    let variables = { id: customerId };
    let variableDefinitions = ['$id: ID!'];
    
    // Handle basic fields
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
    
    // Handle marketing consent separately with correct enum types
    if (updates.acceptsMarketing !== undefined) {
      mutationFields.push('emailMarketingConsent: { marketingState: $marketingState, marketingOptInLevel: $marketingOptInLevel }');
      
      // Use the correct enum values
      variables.marketingState = updates.acceptsMarketing ? 'SUBSCRIBED' : 'UNSUBSCRIBED';
      variables.marketingOptInLevel = 'SINGLE_OPT_IN';
      
      // Add the correct variable types
      variableDefinitions.push('$marketingState: CustomerEmailMarketingState!');
      variableDefinitions.push('$marketingOptInLevel: CustomerMarketingOptInLevel!');
    }
    
    // Build the complete mutation
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
            acceptsMarketing
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
    
    // Execute the GraphQL mutation
    const response = await fetch(SHOPIFY_ADMIN_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': SHOPIFY_ADMIN_ACCESS_TOKEN,
      },
      body: JSON.stringify({
        query: mutation,
        variables: variables,
      }),
    });
    
    const data = await response.json();
    
    // Check for errors
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
    
    // Return the updated customer
    res.json({ 
      customer: data.data.customerUpdate.customer 
    });
    
  } catch (error) {
    console.error('Error updating customer:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  // Optional: Separate endpoint for marketing consent to avoid enum issues
  app.put('/customer/marketing-consent', authenticateToken, async (req, res) => {
    try {
      const { acceptsMarketing } = req.body;
      const customerId = req.user.customerId;
      
      const mutation = `
        mutation updateMarketingConsent(
          $id: ID!
          $marketingState: CustomerEmailMarketingState!
          $marketingOptInLevel: CustomerMarketingOptInLevel!
        ) {
          customerUpdate(
            input: {
              id: $id
              emailMarketingConsent: {
                marketingState: $marketingState
                marketingOptInLevel: $marketingOptInLevel
              }
            }
          ) {
            customer {
              id
              acceptsMarketing
            }
            userErrors {
              field
              message
            }
          }
        }
      `;
      
      const variables = {
        id: customerId,
        marketingState: acceptsMarketing ? 'SUBSCRIBED' : 'UNSUBSCRIBED',
        marketingOptInLevel: 'SINGLE_OPT_IN',
      };
      
      const response = await fetch(SHOPIFY_ADMIN_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': SHOPIFY_ADMIN_ACCESS_TOKEN,
        },
        body: JSON.stringify({
          query: mutation,
          variables: variables,
        }),
      });
      
      const data = await response.json();
      
      if (data.errors || data.data?.customerUpdate?.userErrors?.length > 0) {
        return res.status(400).json({ 
          error: 'Failed to update marketing consent',
          details: data.errors || data.data.customerUpdate.userErrors
        });
      }
      
      res.json({ 
        success: true,
        acceptsMarketing: data.data.customerUpdate.customer.acceptsMarketing 
      });
      
    } catch (error) {
      console.error('Error updating marketing consent:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

// POST /auth/logout - Logout
app.post('/auth/logout', authenticateAppToken, (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.substring(7);
  
  // Remove session
  config.sessions.delete(token);
  
  res.json({ success: true });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    mode: 'combined',
    oauth: true,
    oneTimeCode: true,
    customerEndpoints: true,
    issuer: config.issuer
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Combined Auth Server running on port ${PORT}`);
  console.log(`OAuth endpoints ready at: ${config.issuer}`);
  console.log(`Mobile endpoints ready at: ${config.issuer}/auth/*`);
  console.log(`Customer endpoints ready at: ${config.issuer}/customer/*`);
  console.log(`Admin token configured: ${config.adminToken ? 'YES' : 'NO'}`);
  console.log(`Storefront token configured: ${config.storefrontToken ? 'YES' : 'NO'}`);
});