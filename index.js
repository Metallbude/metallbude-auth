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

// 🔥 PERSISTENT SESSION STORAGE - Add this RIGHT AFTER the config object
const fs = require('fs').promises;
const path = require('path');

const SESSION_FILE = '/tmp/sessions.json';
const REFRESH_TOKENS_FILE = '/tmp/refresh_tokens.json';

// Persistent session storage
const sessions = new Map();
const appRefreshTokens = new Map();

// Load sessions on startup
async function loadPersistedSessionsWithLogging() {
  try {
    console.log('📂 Loading persisted sessions...');
    console.log(`📂 Sessions file: /tmp/sessions.json`);
    console.log(`📂 Refresh tokens file: /tmp/refresh_tokens.json`);
    
    try {
      const sessionData = await fs.readFile('/tmp/sessions.json', 'utf8');
      const sessionEntries = JSON.parse(sessionData);
      
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
      const refreshEntries = JSON.parse(refreshData);
      
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
loadPersistedSessions();

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

// Shopify Customer Account API token management


// 🔥 ADDED: Customer Account API URL for returns
const CUSTOMER_ACCOUNT_API_URL = 'https://shopify.com/48343744676/account/customer/api/2024-10/graphql';

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

// 🔥 ADDED: Return management helper functions
function mapReasonToShopify(reason) {
  const mapping = {
    'size_dimensions': 'SIZE_TOO_LARGE',
    'color_finish': 'COLOR',
    'quality_material': 'QUALITY',
    'style_design': 'NOT_AS_DESCRIBED',
    'transport_damage': 'DAMAGED',
    'assembly_issues': 'DEFECTIVE',
    'defective': 'DEFECTIVE',
    'wrong_item': 'WRONG_ITEM',
    'not_as_described': 'NOT_AS_DESCRIBED',
    'changed_mind': 'NO_LONGER_NEEDED',
    'delivery_delay': 'NO_LONGER_NEEDED',
    'duplicate_order': 'UNWANTED',
    'comfort_ergonomics': 'NOT_AS_DESCRIBED',
    'space_planning': 'NO_LONGER_NEEDED',
    'other': 'OTHER',
  };
  return mapping[reason] || 'OTHER';
}

function mapShopifyReasonToInternal(reason) {
  const mapping = {
    'SIZE_TOO_LARGE': 'size_dimensions',
    'SIZE_TOO_SMALL': 'size_dimensions',
    'COLOR': 'color_finish',
    'QUALITY': 'quality_material',
    'DAMAGED': 'transport_damage',
    'DEFECTIVE': 'defective',
    'WRONG_ITEM': 'wrong_item',
    'NOT_AS_DESCRIBED': 'not_as_described',
    'NO_LONGER_NEEDED': 'changed_mind',
    'UNWANTED': 'duplicate_order',
    'OTHER': 'other',
  };
  return mapping[reason] || 'other';
}

function mapShopifyStatusToInternal(status) {
  const mapping = {
    'REQUESTED': 'pending',
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

// 🔥 ADDED: Check return eligibility using proper Customer Account API
async function checkShopifyReturnEligibility(orderId, customerToken) {
  try {
    console.log('🔍 Checking return eligibility for order:', orderId);

    const query = `
      query returnableFulfillments($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          processedAt
          fulfillmentStatus
          financialStatus
          returnableFulfillments(first: 10) {
            edges {
              node {
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
                          image {
                            url
                          }
                          price {
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
          returns(first: 50) {
            edges {
              node {
                id
                status
                totalQuantity
                returnLineItems(first: 50) {
                  edges {
                    node {
                      fulfillmentLineItem {
                        id
                      }
                      quantity
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
      {
        query,
        variables: { orderId }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        }
      }
    );

    if (response.data.errors) {
      console.error('GraphQL errors:', response.data.errors);
      return {
        eligible: false,
        reason: 'Error checking eligibility',
        returnableItems: []
      };
    }

    const order = response.data.data.order;
    if (!order) {
      return {
        eligible: false,
        reason: 'Order not found',
        returnableItems: []
      };
    }

    // Check order status
    if (order.fulfillmentStatus !== 'FULFILLED') {
      return {
        eligible: false,
        reason: 'Order must be fulfilled to be returned',
        returnableItems: []
      };
    }

    if (['VOIDED', 'REFUNDED'].includes(order.financialStatus)) {
      return {
        eligible: false,
        reason: 'Order has been voided or refunded',
        returnableItems: []
      };
    }

    // Get returnable items
    const returnableFulfillments = order.returnableFulfillments.edges || [];
    const existingReturns = order.returns.edges || [];
    
    // Track items already returned
    const returnedItemIds = new Set();
    for (const returnEdge of existingReturns) {
      const returnStatus = returnEdge.node.status;
      if (['REQUESTED', 'OPEN', 'PROCESSING'].includes(returnStatus)) {
        const returnLineItems = returnEdge.node.returnLineItems.edges || [];
        for (const lineItemEdge of returnLineItems) {
          const fulfillmentLineItemId = lineItemEdge.node.fulfillmentLineItem.id;
          returnedItemIds.add(fulfillmentLineItemId);
        }
      }
    }

    const returnableItems = [];
    
    for (const fulfillmentEdge of returnableFulfillments) {
      const fulfillment = fulfillmentEdge.node;
      const lineItems = fulfillment.fulfillmentLineItems.edges || [];
      
      for (const lineItemEdge of lineItems) {
        const fulfillmentLineItem = lineItemEdge.node;
        const fulfillmentLineItemId = fulfillmentLineItem.id;
        
        // Skip if already returned
        if (returnedItemIds.has(fulfillmentLineItemId)) {
          continue;
        }
        
        const lineItem = fulfillmentLineItem.lineItem;
        const variant = lineItem.variant;
        
        returnableItems.push({
          id: lineItem.id,
          fulfillmentLineItemId: fulfillmentLineItemId,
          title: lineItem.title,
          quantity: fulfillmentLineItem.quantity,
          variant: {
            id: variant.id,
            title: variant.title,
            price: variant.price.amount,
            image: variant.image?.url,
          },
        });
      }
    }

    console.log(`✅ Found ${returnableItems.length} returnable items`);

    return {
      eligible: returnableItems.length > 0,
      reason: returnableItems.length === 0 ? 'No returnable items found' : null,
      returnableItems: returnableItems,
      existingReturns: existingReturns.length,
    };

  } catch (error) {
    console.error('❌ Error checking return eligibility:', error);
    return {
      eligible: false,
      reason: 'Error checking return eligibility',
      returnableItems: []
    };
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
      
      returnLineItems.push({
        fulfillmentLineItemId: matchingItem.fulfillmentLineItemId,
        quantity: item.quantity,
        returnReason: mapReasonToShopify(returnRequest.reason),
        customerNote: returnRequest.additionalNotes || getReasonDescription(returnRequest.reason),
      });
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

    const response = await axios.post(
      CUSTOMER_ACCOUNT_API_URL,
      {
        query: mutation,
        variables: {
          orderId: returnRequest.orderId,
          returnLineItems: returnLineItems,
        },
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${customerToken}`,
        }
      }
    );

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
    return {
      success: false,
      error: error.message
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
                      createdAt
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
          const lineItem = lineItemEdge.node;
          const fulfillmentLineItem = lineItem.fulfillmentLineItem;
          const originalLineItem = fulfillmentLineItem.lineItem;
          const variant = originalLineItem.variant;
          
          items.push({
            lineItemId: originalLineItem.id,
            productId: variant.id,
            title: originalLineItem.title,
            imageUrl: variant.image?.url,
            quantity: lineItem.quantity,
            price: parseFloat(variant.price.amount) || 0.0,
            sku: variant.id,
            variantTitle: variant.title,
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
              ? (returnLineItems[0].node.customerNote || '') 
              : '',
          preferredResolution: 'refund',
          customerEmail: '',
          requestDate: returnData.createdAt,
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
  
    const refreshData = config.appRefreshTokens.get(refreshToken);
    if (!refreshData) {
      return res.status(401).json({ success: false, error: 'Invalid refresh token' });
    }
  
    // Check if refresh token is expired
    if (refreshData.expiresAt < Date.now()) {
      config.appRefreshTokens.delete(refreshToken);
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
  let session = sessions.get(token);
  
  if (!session) {
    console.log(`❌ Session not found for token: ${token.substring(0, 20)}...`);
    
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

    if (response.data.errors) {
      console.error('❌ Profile fetch errors:', response.data.errors);
      return res.status(500).json({ error: 'Failed to fetch profile' });
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

    if (response.data.errors) {
      console.error('❌ Orders fetch errors:', response.data.errors);
      return res.json({ orders: [] });
    }

    const orderEdges = response.data?.data?.customer?.orders?.edges || [];
    console.log(`✅ Successfully fetched ${orderEdges.length} orders using SIMPLE query`);
    
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
    console.error('❌ Orders fetch error:', error);
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
            const returnLineItem = itemEdge.node;
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
                id: returnLineItem.fulfillmentLineItem.id,
                quantity: returnLineItem.fulfillmentLineItem.quantity,
                lineItem: {
                  id: returnLineItem.fulfillmentLineItem.lineItem.id,
                  title: returnLineItem.fulfillmentLineItem.lineItem.title,
                  variant: returnLineItem.fulfillmentLineItem.lineItem.variant
                }
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

// GET /customer/wishlist - Customer wishlist/favorites
app.get('/customer/wishlist', authenticateAppToken, async (req, res) => {
  try {
    console.log('❤️ Fetching wishlist for:', req.session.email);

    // Get customer metafield containing wishlist
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

    let wishlistProductIds = [];
    const metafield = response.data.data?.customer?.metafield;
    if (metafield?.value) {
      try {
        wishlistProductIds = JSON.parse(metafield.value);
      } catch (e) {
        wishlistProductIds = metafield.value.split(',').filter(id => id.trim());
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
              minVariantPrice {
                amount
                currencyCode
              }
            }
            compareAtPriceRange {
              minVariantPrice {
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
                  availableForSale
                  priceV2 {
                    amount
                    currencyCode
                  }
                  compareAtPriceV2 {
                    amount
                    currencyCode
                  }
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
            availableForSale
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
    const wishlist = products.filter(product => product !== null).map(product => ({
      id: product.id,
      title: product.title,
      handle: product.handle,
      description: product.description,
      price: {
        amount: product.priceRange.minVariantPrice.amount,
        currencyCode: product.priceRange.minVariantPrice.currencyCode
      },
      compareAtPrice: product.compareAtPriceRange?.minVariantPrice ? {
        amount: product.compareAtPriceRange.minVariantPrice.amount,
        currencyCode: product.compareAtPriceRange.minVariantPrice.currencyCode
      } : null,
      image: product.featuredImage?.url,
      images: product.images.edges.map(edge => edge.node),
      variants: product.variants.edges.map(edge => edge.node),
      availableForSale: product.availableForSale,
      totalInventory: product.totalInventory,
      productType: product.productType,
      vendor: product.vendor,
      tags: product.tags,
      isOnSale: product.compareAtPriceRange?.minVariantPrice ? 
        parseFloat(product.compareAtPriceRange.minVariantPrice.amount) > parseFloat(product.priceRange.minVariantPrice.amount) : false,
      addedToWishlistAt: new Date().toISOString() // You might want to track this separately
    }));

    console.log(`✅ Fetched ${wishlist.length} wishlist items`);
    res.json({ wishlist });

  } catch (error) {
    console.error('❌ Wishlist fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch wishlist' });
  }
});

// POST /customer/wishlist - Add/remove from wishlist
app.post('/customer/wishlist', authenticateAppToken, async (req, res) => {
  try {
    const { productId, action = 'add' } = req.body; // action: 'add' or 'remove'
    console.log(`❤️ ${action === 'add' ? 'Adding to' : 'Removing from'} wishlist:`, productId);

    // Get current wishlist
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
      } catch (e) {
        currentWishlist = existingMetafield.value.split(',').filter(id => id.trim());
      }
    }

    // Update wishlist
    if (action === 'add' && !currentWishlist.includes(productId)) {
      currentWishlist.push(productId);
    } else if (action === 'remove') {
      currentWishlist = currentWishlist.filter(id => id !== productId);
    }

    // Save updated wishlist
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

    const updateResponse = await axios.post(
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

    console.log(`✅ Wishlist updated successfully - ${action}ed product ${productId}`);
    res.json({ 
      success: true, 
      action,
      productId,
      wishlistCount: currentWishlist.length 
    });

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
    
    console.log('🔑 Creating Shopify customer access token for:', customerEmail);
    
    // Use Shopify Customer Account API to create access token
    const mutation = `
      mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
        customerAccessTokenCreate(input: $input) {
          customerAccessToken {
            accessToken
            expiresAt
          }
          customerUserErrors {
            code
            field
            message
          }
        }
      }
    `;
    
    // Note: You need the customer's password for this
    // Since we're using passwordless auth, we need to use a different approach
    
    // 🔥 ALTERNATIVE: Use Admin API to create customer access token directly
    const adminMutation = `
      mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
        customerAccessTokenCreate(input: $input) {
          customerAccessToken {
            accessToken
            expiresAt
          }
          userErrors {
            field
            message
          }
        }
      }
    `;
    
    // First, get the customer ID from Shopify
    const customerQuery = `
      query getCustomer($email: String!) {
        customers(first: 1, query: $email) {
          edges {
            node {
              id
              email
              phone
            }
          }
        }
      }
    `;
    
    const customerResponse = await axios.post(
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
    
    if (customerResponse.data.errors) {
      console.error('❌ Error fetching customer:', customerResponse.data.errors);
      return res.status(500).json({ error: 'Failed to fetch customer' });
    }
    
    const customers = customerResponse.data.data?.customers?.edges || [];
    if (customers.length === 0) {
      console.error('❌ Customer not found:', customerEmail);
      return res.status(404).json({ error: 'Customer not found in Shopify' });
    }
    
    const customer = customers[0].node;
    console.log('✅ Found customer:', customer.id);
    
    // 🔥 WORKAROUND: Since we can't create customer access tokens via Admin API
    // We'll create a long-lived session token that the app can use
    
    // For now, return a mock token that represents the customer
    const mockCustomerToken = Buffer.from(JSON.stringify({
      customerId: customer.id,
      email: customer.email,
      createdAt: Date.now(),
      expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
    })).toString('base64');
    
    console.log('✅ Created mock customer token for app usage');
    
    res.json({
      success: true,
      customerAccessToken: mockCustomerToken,
      expiresAt: new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)).toISOString(),
    });
    
  } catch (error) {
    console.error('❌ Error creating Shopify customer token:', error);
    res.status(500).json({ 
      error: 'Failed to create customer access token' 
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
                minVariantPrice {
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
                    priceV2 {
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
      const compareAtPrice = node.compareAtPriceRange?.minVariantPrice?.amount 
        ? parseFloat(node.compareAtPriceRange.minVariantPrice.amount) 
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
      } catch (e) {
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
      } catch (e) {
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
      } catch (e) {
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
      } catch (e) {
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
                  priceV2 {
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

    console.log('🔍 Checking return eligibility for order:', orderId);
    
    // 🔥 REMOVED: await ensureValidShopifyToken(customerEmail);
    console.log('🔍 Using Shopify Admin API directly to check return eligibility...');

    // Get real order data to check return eligibility
    const query = `
      query checkReturnEligibility($orderId: ID!) {
        order(id: $orderId) {
          id
          name
          processedAt
          displayFulfillmentStatus
          displayFinancialStatus
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
                  priceV2 {
                    amount
                    currencyCode
                  }
                  image {
                    url
                    altText
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
          fulfillments(first: 10) {
            edges {
              node {
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
            }
          }
          returns(first: 10) {
            edges {
              node {
                id
                status
                returnLineItems(first: 250) {
                  edges {
                    node {
                      fulfillmentLineItem {
                        lineItem {
                          id
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
      console.error('❌ Return eligibility check errors:', response.data.errors);
      return res.status(404).json({
        eligible: false,
        reason: 'Order not found',
        returnableItems: []
      });
    }

    const order = response.data.data.order;
    if (!order) {
      return res.status(404).json({
        eligible: false,
        reason: 'Order not found',
        returnableItems: []
      });
    }

    // Check basic return eligibility
    const canReturn = order.displayFulfillmentStatus === 'FULFILLED' && 
                     order.displayFinancialStatus !== 'REFUNDED';

    if (!canReturn) {
      return res.json({
        eligible: false,
        reason: order.displayFulfillmentStatus !== 'FULFILLED' ? 
                'Order must be fulfilled to be returned' :
                'Order has already been refunded',
        returnableItems: []
      });
    }

    // Get items already returned
    const returnedLineItemIds = new Set();
    order.returns.edges.forEach(returnEdge => {
      returnEdge.node.returnLineItems.edges.forEach(returnLineItemEdge => {
        const lineItemId = returnLineItemEdge.node.fulfillmentLineItem.lineItem.id;
        returnedLineItemIds.add(lineItemId);
      });
    });

    // Build returnable items list
    const returnableItems = [];
    order.lineItems.edges.forEach(lineItemEdge => {
      const lineItem = lineItemEdge.node;
      
      // Skip if already returned
      if (returnedLineItemIds.has(lineItem.id)) {
        return;
      }

      // Add to returnable items
      returnableItems.push({
        id: lineItem.id,
        lineItemId: lineItem.id,
        fulfillmentLineItemId: `fulfillment_${lineItem.id}`,
        title: lineItem.title,
        quantity: lineItem.quantity,
        variant: {
          id: lineItem.variant.id,
          title: lineItem.variant.title,
          sku: lineItem.variant.sku,
          price: lineItem.variant.priceV2.amount,
          image: lineItem.variant.image?.url || 'https://via.placeholder.com/150',
          product: lineItem.variant.product
        }
      });
    });

    const eligibility = {
      eligible: returnableItems.length > 0,
      reason: returnableItems.length === 0 ? 'No returnable items found' : null,
      returnableItems: returnableItems,
      existingReturns: order.returns.edges.length,
      orderInfo: {
        id: order.id,
        name: order.name,
        processedAt: order.processedAt,
        fulfillmentStatus: order.displayFulfillmentStatus,
        financialStatus: order.displayFinancialStatus
      }
    };
    
    console.log(`✅ Return eligibility checked using Admin API - ${returnableItems.length} returnable items`);
    res.json(eligibility);
    
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
      customer: customerEmail
    });

    // Step 1: Submit to Shopify using Customer Account API
    const shopifyResult = await submitShopifyReturnRequest(returnRequest, customerToken);
    
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
      status: 'pending',
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

// 🔥 UPDATED: Get return history from Shopify Customer Account API
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
    
    // Get returns from Shopify Customer Account API
    const shopifyReturns = await getShopifyCustomerReturns(customerToken);
    
    // Optionally merge with backend data
    // const backendReturns = await getBackendReturns(customerEmail);
    // const mergedReturns = mergeReturns(shopifyReturns, backendReturns);
    
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
    returnManagement: true,
    issuer: config.issuer
  });
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
      sessionsFile: '/tmp/sessions.json',
      refreshTokensFile: '/tmp/refresh_tokens.json'
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
      const sessionEntries = JSON.parse(sessionData);
      diskSessions = sessionEntries;
      sessionsFileExists = true;
      console.log(`📂 Found ${sessionEntries.length} sessions on disk`);
    } catch (error) {
      console.log('📂 No sessions file found on disk');
    }
    
    // Check refresh tokens file
    try {
      const refreshData = await fs.readFile('/tmp/refresh_tokens.json', 'utf8');
      const refreshEntries = JSON.parse(refreshData);
      diskRefreshTokens = refreshEntries;
      refreshTokensFileExists = true;
      console.log(`📂 Found ${refreshEntries.length} refresh tokens on disk`);
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
      config.appRefreshTokens.delete(refreshToken);
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
  const activeRefreshTokens = config.appRefreshTokens.size;
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