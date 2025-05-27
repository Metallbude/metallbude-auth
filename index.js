require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const { URL } = require('url');

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
  privateKey,
  publicKey,
  clients: {
    'shopify_client_id': {
      client_secret: process.env.SHOPIFY_CLIENT_SECRET || 'your_client_secret_here',
      redirect_uris: [
        'https://account.metallbude.com/authentication/login/external/callback',
        'https://shopify.com/authentication/48343744676/login/external/callback',
        'https://metallbude-de.myshopify.com/account/auth/callback',
        'https://metallbude-de.myshopify.com/account/connect/callback'
      ]
    }
  },
  // Storage for authorization codes and sessions
  authorizationCodes: new Map(),
  accessTokens: new Map(),
  refreshTokens: new Map()
};

// JWKS endpoint - returns the public key in JWKS format
app.get('/.well-known/jwks.json', (req, res) => {
  const key = crypto.createPublicKey(config.publicKey);
  const jwk = key.export({ format: 'jwk' });

  res.json({
    keys: [
      {
        kty: jwk.kty,
        kid: 'oidc-key-1',
        use: 'sig',
        alg: 'RS256',
        n: jwk.n,
        e: jwk.e
      }
    ]
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

// Authorization endpoint - Shopify redirects users here
app.get('/authorize', async (req, res) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method
  } = req.query;

  console.log('Authorization request:', { client_id, redirect_uri, scope, state });

  // Validate required parameters
  if (!client_id || !redirect_uri || !response_type || !scope) {
    return res.status(400).send('Missing required parameters');
  }

  // Validate client and redirect URI
  const client = config.clients[client_id];
  if (!client) {
    return res.status(400).send('Invalid client_id');
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send(`Invalid redirect_uri. Allowed URIs: ${client.redirect_uris.join(', ')}`);
  }

  // Validate response type
  if (response_type !== 'code') {
    return redirectWithError(res, redirect_uri, 'unsupported_response_type', state);
  }

  // In a real implementation, you would show a login form here
  // For now, we'll simulate a login page
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Metallbude Login</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #333; color: white; border: none; cursor: pointer; }
      </style>
    </head>
    <body>
      <h2>Metallbude Anmeldung</h2>
      <form method="POST" action="/authorize/callback">
        <input type="hidden" name="client_id" value="${client_id}">
        <input type="hidden" name="redirect_uri" value="${redirect_uri}">
        <input type="hidden" name="scope" value="${scope}">
        <input type="hidden" name="state" value="${state || ''}">
        <input type="hidden" name="nonce" value="${nonce || ''}">
        <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
        <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
        
        <input type="email" name="email" placeholder="E-Mail" required>
        <input type="password" name="password" placeholder="Passwort" required>
        <button type="submit">Anmelden</button>
      </form>
    </body>
    </html>
  `);
});

// Handle login form submission
app.post('/authorize/callback', async (req, res) => {
  const {
    email,
    password,
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method
  } = req.body;

  // Here you would validate the user credentials
  // For this example, we'll accept any email/password
  // In production, you should validate against your user database
  
  // Generate authorization code
  const code = crypto.randomBytes(32).toString('hex');
  const authInfo = {
    client_id,
    redirect_uri,
    scope,
    nonce,
    code_challenge,
    code_challenge_method,
    user: {
      sub: crypto.createHash('sha256').update(email).digest('hex'),
      email: email,
      email_verified: true,
      name: email.split('@')[0],
      given_name: email.split('@')[0],
      family_name: '',
      preferred_username: email,
      updated_at: Math.floor(Date.now() / 1000)
    },
    created_at: Date.now()
  };

  // Store the code with a 10-minute expiration
  config.authorizationCodes.set(code, authInfo);
  setTimeout(() => {
    config.authorizationCodes.delete(code);
  }, 10 * 60 * 1000);

  // Redirect back to Shopify with the code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append('code', code);
  if (state) {
    redirectUrl.searchParams.append('state', state);
  }

  console.log(`Authorization successful for ${email}. Redirecting to: ${redirectUrl.toString()}`);
  res.redirect(redirectUrl.toString());
});

// Token endpoint - Shopify exchanges code for tokens here
app.post('/token', async (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier,
    refresh_token
  } = req.body;

  console.log('Token request:', { grant_type, client_id, redirect_uri });

  // Validate client credentials
  const client = config.clients[client_id];
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }

  if (grant_type === 'authorization_code') {
    // Handle authorization code grant
    const authInfo = config.authorizationCodes.get(code);
    if (!authInfo) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }

    // Validate redirect URI
    if (authInfo.redirect_uri !== redirect_uri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch'
      });
    }

    // Validate PKCE if used
    if (authInfo.code_challenge) {
      if (!code_verifier) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Code verifier required'
        });
      }

      const verifierChallenge = crypto
        .createHash('sha256')
        .update(code_verifier)
        .digest('base64url');

      if (verifierChallenge !== authInfo.code_challenge) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid code verifier'
        });
      }
    }

    // Delete the used code
    config.authorizationCodes.delete(code);

    // Generate tokens
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshTokenValue = crypto.randomBytes(32).toString('hex');
    const expiresIn = 3600; // 1 hour

    // Store tokens
    const tokenInfo = {
      user: authInfo.user,
      scope: authInfo.scope,
      client_id,
      expires_at: Date.now() + expiresIn * 1000
    };

    config.accessTokens.set(accessToken, tokenInfo);
    config.refreshTokens.set(refreshTokenValue, {
      ...tokenInfo,
      access_token: accessToken
    });

    // Generate ID token
    const idToken = generateIdToken(authInfo.user, client_id, authInfo.nonce, expiresIn);

    console.log(`Tokens issued for ${authInfo.user.email}`);

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
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid refresh token'
      });
    }

    // Generate new access token
    const newAccessToken = crypto.randomBytes(32).toString('hex');
    const expiresIn = 3600;

    // Update token info
    tokenInfo.expires_at = Date.now() + expiresIn * 1000;
    config.accessTokens.set(newAccessToken, tokenInfo);

    // Delete old access token
    if (tokenInfo.access_token) {
      config.accessTokens.delete(tokenInfo.access_token);
    }
    tokenInfo.access_token = newAccessToken;

    const idToken = generateIdToken(tokenInfo.user, client_id, null, expiresIn);

    res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refresh_token,
      id_token: idToken
    });

  } else {
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code and refresh_token grant types are supported'
    });
  }
});

// UserInfo endpoint - Shopify can get user info here
app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Missing or invalid access token'
    });
  }

  const accessToken = authHeader.substring(7);
  const tokenInfo = config.accessTokens.get(accessToken);

  if (!tokenInfo || tokenInfo.expires_at < Date.now()) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
  }

  const scopes = tokenInfo.scope.split(' ');
  const userInfo = { sub: tokenInfo.user.sub };

  if (scopes.includes('email')) {
    userInfo.email = tokenInfo.user.email;
    userInfo.email_verified = tokenInfo.user.email_verified;
  }

  if (scopes.includes('profile')) {
    userInfo.name = tokenInfo.user.name;
    userInfo.given_name = tokenInfo.user.given_name;
    userInfo.family_name = tokenInfo.user.family_name;
    userInfo.preferred_username = tokenInfo.user.preferred_username;
    userInfo.updated_at = tokenInfo.user.updated_at;
  }

  console.log(`UserInfo requested for ${tokenInfo.user.email}`);
  res.json(userInfo);
});

// Logout endpoint
app.get('/logout', (req, res) => {
  const { id_token_hint, post_logout_redirect_uri, state } = req.query;
  
  // In a real implementation, you would validate the id_token_hint
  // and invalidate any active sessions
  
  if (post_logout_redirect_uri) {
    const redirectUrl = new URL(post_logout_redirect_uri);
    if (state) {
      redirectUrl.searchParams.append('state', state);
    }
    return res.redirect(redirectUrl.toString());
  }
  
  res.send('You have been logged out successfully.');
});

// Helper function to generate an ID token
function generateIdToken(user, clientId, nonce, expiresIn) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: config.issuer,
    sub: user.sub,
    aud: clientId,
    exp: now + expiresIn,
    iat: now,
    auth_time: now,
    email: user.email,
    email_verified: user.email_verified,
    name: user.name,
    given_name: user.given_name,
    family_name: user.family_name,
    preferred_username: user.preferred_username,
    updated_at: user.updated_at
  };

  if (nonce) {
    payload.nonce = nonce;
  }

  return jwt.sign(payload, config.privateKey, {
    algorithm: 'RS256',
    keyid: 'oidc-key-1'
  });
}

// Helper function to redirect with an error
function redirectWithError(res, redirectUri, error, state) {
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.append('error', error);
  if (state) {
    redirectUrl.searchParams.append('state', state);
  }
  return res.redirect(redirectUrl.toString());
}

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    issuer: config.issuer,
    openid_config: `${config.issuer}/.well-known/openid-configuration`
  });
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`OIDC Provider running on port ${PORT}`);
  console.log(`OpenID Configuration: ${config.issuer}/.well-known/openid-configuration`);
  console.log(`JWKS: ${config.issuer}/.well-known/jwks.json`);
});

// Clean up old tokens periodically
setInterval(() => {
  const now = Date.now();
  
  for (const [token, info] of config.accessTokens.entries()) {
    if (info.expires_at < now) {
      config.accessTokens.delete(token);
    }
  }
}, 60 * 60 * 1000);