import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import { URL } from 'url';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
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

// Store keys and other configuration
const config = {
  issuer: 'https://auth.metallbude.com',
  privateKey,
  publicKey,
  clients: {
    'shopify_client_id': {
      client_secret: 'shopify_client_secret',
      redirect_uris: [
        'https://metallbude-de.myshopify.com/account/auth/callback',
        'https://metallbude-de.myshopify.com/account/connect/callback',
        'http://localhost:3000/callback' // For testing
      ]
    }
  },
  // In-memory storage for authorization codes and tokens
  authorizationCodes: new Map(),
  accessTokens: new Map()
};

// Test user
const testUser = {
  sub: 'user_123456789',
  email: 'rudolf.klause@metallbude.com',
  email_verified: true,
  name: 'Rudolf Klause',
  given_name: 'Rudolf',
  family_name: 'Klause',
  preferred_username: 'rudolf.klause',
  updated_at: Math.floor(Date.now() / 1000)
};

// JWKS endpoint - returns the public key in JWKS format
app.get('/.well-known/jwks.json', (req, res) => {
  // Extract the modulus and exponent from the public key
  const pem = config.publicKey;
  const pemHeader = '-----BEGIN PUBLIC KEY-----';
  const pemFooter = '-----END PUBLIC KEY-----';
  const pemContents = pem.substring(
    pemHeader.length,
    pem.length - pemFooter.length - 1
  ).replace(/\n/g, '');
  
  const binaryDer = Buffer.from(pemContents, 'base64');
  const key = crypto.createPublicKey(pem);
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
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: [
      'sub', 'iss', 'auth_time', 'name', 'given_name', 'family_name',
      'email', 'email_verified', 'preferred_username', 'updated_at'
    ]
  });
});

// Authorization endpoint
app.get('/authorize', (req, res) => {
  const {
    client_id,
    redirect_uri,
    response_type,
    scope,
    state,
    nonce
  } = req.query;

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
    return res.status(400).send('Invalid redirect_uri');
  }

  // Validate response type
  if (response_type !== 'code') {
    return redirectWithError(redirect_uri, 'unsupported_response_type', state);
  }

  // Generate authorization code
  const code = crypto.randomBytes(32).toString('hex');
  const authInfo = {
    client_id,
    redirect_uri,
    scope,
    nonce,
    user: testUser,
    created_at: Date.now()
  };

  // Store the code with a 10-minute expiration
  config.authorizationCodes.set(code, authInfo);
  setTimeout(() => {
    config.authorizationCodes.delete(code);
  }, 10 * 60 * 1000);

  // Redirect back to the client with the code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append('code', code);
  if (state) {
    redirectUrl.searchParams.append('state', state);
  }

  console.log(`Authorization successful for ${testUser.email}. Redirecting to: ${redirectUrl.toString()}`);
  res.redirect(redirectUrl.toString());
});

// Token endpoint
app.post('/token', (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret
  } = req.body;

  // Validate grant type
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code grant type is supported'
    });
  }

  // Validate client credentials
  const client = config.clients[client_id];
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }

  // Validate authorization code
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

  // Delete the used code
  config.authorizationCodes.delete(code);

  // Generate access token
  const accessToken = crypto.randomBytes(32).toString('hex');
  const expiresIn = 3600; // 1 hour
  const tokenInfo = {
    user: authInfo.user,
    scope: authInfo.scope,
    client_id,
    expires_at: Date.now() + expiresIn * 1000
  };

  // Store the access token
  config.accessTokens.set(accessToken, tokenInfo);
  setTimeout(() => {
    config.accessTokens.delete(accessToken);
  }, expiresIn * 1000);

  // Generate ID token
  const idToken = generateIdToken(
    authInfo.user,
    client_id,
    authInfo.nonce,
    expiresIn
  );

  console.log(`Token issued for ${authInfo.user.email}`);
  
  // Return the tokens
  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    id_token: idToken
  });
});

// UserInfo endpoint
app.get('/userinfo', (req, res) => {
  // Extract the access token from the Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Missing or invalid access token'
    });
  }

  const accessToken = authHeader.substring(7);
  const tokenInfo = config.accessTokens.get(accessToken);

  // Validate the access token
  if (!tokenInfo) {
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired access token'
    });
  }

  // Check if the token has expired
  if (tokenInfo.expires_at < Date.now()) {
    config.accessTokens.delete(accessToken);
    return res.status(401).json({
      error: 'invalid_token',
      error_description: 'Access token has expired'
    });
  }

  // Return the user info
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

  // Add nonce if provided
  if (nonce) {
    payload.nonce = nonce;
  }

  // Sign the ID token with the private key
  return jwt.sign(payload, config.privateKey, {
    algorithm: 'RS256',
    keyid: 'oidc-key-1'
  });
}

// Helper function to redirect with an error
function redirectWithError(redirectUri, error, state) {
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.append('error', error);
  if (state) {
    redirectUrl.searchParams.append('state', state);
  }
  return res.redirect(redirectUrl.toString());
}

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`OIDC Provider running on port ${PORT}`);
  console.log(`OpenID Configuration available at: ${config.issuer}/.well-known/openid-configuration`);
});
