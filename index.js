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
  adminToken: process.env.SHOPIFY_ADMIN_TOKEN,
  apiUrl: process.env.SHOPIFY_API_URL || 'https://metallbude-de.myshopify.com/api/2024-10/graphql.json',
  adminApiUrl: process.env.SHOPIFY_ADMIN_API_URL || 'https://metallbude-de.myshopify.com/admin/api/2024-10/graphql.json',
  cleverpushChannelId: process.env.CLEVERPUSH_CHANNEL_ID,
  cleverpushApiKey: process.env.CLEVERPUSH_API_KEY,
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
  customerEmails: new Map()
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
    
    console.log('Set default address response:', JSON.stringify(response.data, null, 2));
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

  const accessToken = crypto.randomBytes(32).toString('hex');
  config.sessions.set(accessToken, {
    email,
    customerId,
    customerData,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000
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
  
  if (!session && token.length === 64) {
    console.log('Creating temporary session for existing token');
    session = {
      email: 'unknown@example.com',
      customerId: 'gid://shopify/Customer/temporary',
      customerData: {
        id: 'gid://shopify/Customer/temporary',
        email: 'unknown@example.com',
        displayName: 'User'
      },
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    };
  }
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid token' });
  }

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

    if (response.data.errors) {
      console.error('GraphQL errors:', response.data.errors);
      return res.json({ orders: [] });
    }

    const orderEdges = response.data?.data?.customer?.orders?.edges || [];
    console.log(`Found ${orderEdges.length} orders`);
    
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

// POST /customer/address - Create/Update address via customerAddressCreate/Update (ADMIN API APPROACH)
app.post('/customer/address', authenticateAppToken, async (req, res) => {
  try {
    const { address } = req.body;
    const customerId = req.session.customerId;
    
    console.log('Creating address by setting as default address');
    
    const mutation = `
      mutation customerUpdate($input: CustomerInput!) {
        customerUpdate(input: $input) {
          customer {
            id
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
              firstName: address.firstName || '',
              lastName: address.lastName || '',
              company: address.company || '',
              address1: address.address1 || '',
              address2: address.address2 || '',
              city: address.city || '',
              province: address.province || '',
              country: address.country || 'DE',
              zip: address.zip || '',
              phone: address.phone || ''
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
    
    if (response.data.errors) {
      return res.status(400).json({ error: 'Failed to create address', details: response.data.errors });
    }
    
    const result = response.data.data?.customerUpdate;
    if (result?.userErrors?.length > 0) {
      return res.status(400).json({ error: 'Failed to create address', details: result.userErrors });
    }
    
    if (result?.customer?.defaultAddress) {
      res.json({ 
        address: {
          ...result.customer.defaultAddress,
          isDefault: true
        }
      });
    } else {
      res.status(400).json({ error: 'Failed to create address' });
    }
    
  } catch (error) {
    console.error('Error creating address:', error);
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
app.post('/auth/logout', authenticateAppToken, (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.substring(7);
  
  config.sessions.delete(token);
  
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
                minVariantPrice {
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
      const compareAtPrice = node.compareAtPriceRange?.minVariantPrice?.amount 
        ? parseFloat(node.compareAtPriceRange.minVariantPrice.amount) 
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