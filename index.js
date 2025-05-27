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
  apiUrl: process.env.SHOPIFY_API_URL || 'https://metallbude-de.myshopify.com/api/2024-10/graphql.json',
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

// Request one-time code endpoint (for Flutter app)
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'E-Mail-Adresse ist erforderlich' });
  }

  const code = generateVerificationCode();
  const sessionId = generateSessionId();

  config.verificationCodes.set(sessionId, {
    email,
    code,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000,
    isNewCustomer: !config.customerEmails.has(email)
  });

  await sendVerificationEmail(email, code);
  console.log(`Mobile app: Generated code for ${email}: ${code}`);

  res.json({
    success: true,
    isNewCustomer: !config.customerEmails.has(email),
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

  // Mark customer as registered
  if (!config.customerEmails.has(email)) {
    const customerId = `gid://shopify/Customer/${crypto.randomBytes(8).toString('hex')}`;
    config.customerEmails.set(email, customerId);
  }

  // Generate access token for the app
  const accessToken = crypto.randomBytes(32).toString('hex');
  config.sessions.set(accessToken, {
    email,
    customerId: config.customerEmails.get(email),
    createdAt: Date.now()
  });

  config.verificationCodes.delete(sessionId);

  res.json({
    success: true,
    accessToken,
    customer: {
      id: config.customerEmails.get(email),
      email: email,
      displayName: email.split('@')[0]
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    mode: 'combined',
    oauth: true,
    oneTimeCode: true,
    issuer: config.issuer
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Combined Auth Server running on port ${PORT}`);
  console.log(`OAuth endpoints ready at: ${config.issuer}`);
  console.log(`Mobile endpoints ready at: ${config.issuer}/auth/*`);
});