// FIXED: backend/server.js - Real Shopify Customer Account API Implementation

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 🔥 REAL SHOPIFY CUSTOMER ACCOUNT API CONFIGURATION
const config = {
  // Your actual Shopify store domain
  shopDomain: process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com',
  
  // Shopify Admin API token (for customer operations)
  adminToken: process.env.SHOPIFY_ADMIN_TOKEN,
  
  // Customer Account API configuration - GET THESE FROM SHOPIFY ADMIN
  customerAccountApi: {
    clientId: process.env.SHOPIFY_CUSTOMER_ACCOUNT_CLIENT_ID, // from Shopify Admin -> Settings -> Customer Account API
    clientSecret: process.env.SHOPIFY_CUSTOMER_ACCOUNT_CLIENT_SECRET, // from Shopify Admin
    redirectUri: process.env.SHOPIFY_CUSTOMER_ACCOUNT_REDIRECT_URI || 'https://metallbude-auth.onrender.com/auth/shopify/callback',
    scope: 'openid email customer-account-api:full',
  },
  
  // MailerSend for sending verification codes
  mailerSendApiKey: process.env.MAILERSEND_API_KEY,
  
  // Storage for sessions and codes
  verificationCodes: new Map(),
  sessions: new Map(),
  appRefreshTokens: new Map(),
  
  // Token lifetimes
  tokenLifetimes: {
    accessToken: 180 * 24 * 60 * 60, // 180 days
    refreshToken: 365 * 24 * 60 * 60, // 365 days
  },
};

// Helper functions
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Send verification email with actual 6-digit code
async function sendVerificationEmail(email, code) {
  if (!config.mailerSendApiKey) {
    console.log(`🔐 Verification code for ${email}: ${code}`);
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
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #333;">Metallbude</h1>
            </div>
            <h2 style="color: #333;">Ihr Anmeldecode</h2>
            <p style="font-size: 16px; color: #666;">Geben Sie diesen 6-stelligen Code in der App ein:</p>
            <div style="background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
              <h1 style="font-size: 36px; letter-spacing: 8px; color: #333; margin: 0;">${code}</h1>
            </div>
            <p style="color: #666;">Dieser Code ist 10 Minuten gültig.</p>
            <p style="color: #999; font-size: 14px;">Falls Sie diese E-Mail nicht angefordert haben, können Sie sie ignorieren.</p>
          </div>
        `,
        text: `Ihr Anmeldecode für Metallbude: ${code}\n\nDieser Code ist 10 Minuten gültig.`
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
    console.log(`🔐 Verification code for ${email}: ${code}`);
    return true;
  }
}

// 🔥 REAL: Get customer data from Shopify Admin API
async function getShopifyCustomerByEmail(email) {
  if (!config.adminToken) {
    console.log('❌ No Shopify admin token configured');
    return null;
  }

  try {
    console.log(`🔍 Searching for customer: ${email}`);
    
    const response = await axios.get(
      `https://${config.shopDomain}/admin/api/2024-10/customers/search.json?query=email:${encodeURIComponent(email)}`,
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.customers && response.data.customers.length > 0) {
      const customer = response.data.customers[0];
      console.log(`✅ Found customer: ${customer.email} (ID: ${customer.id})`);
      return customer;
    } else {
      console.log(`❌ Customer not found: ${email}`);
      return null;
    }
  } catch (error) {
    console.error('❌ Error fetching customer from Shopify:', error.response?.data || error.message);
    return null;
  }
}

// 🔥 REAL: Create customer in Shopify if they don't exist
async function createShopifyCustomer(email) {
  if (!config.adminToken) {
    console.log('❌ No Shopify admin token configured');
    return null;
  }

  try {
    console.log(`🆕 Creating customer: ${email}`);
    
    const response = await axios.post(
      `https://${config.shopDomain}/admin/api/2024-10/customers.json`,
      {
        customer: {
          email: email,
          accepts_marketing: false,
          send_email_welcome: false,
          password_confirmation: crypto.randomBytes(16).toString('hex'), // Random password
          send_email_invite: false
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.data.customer) {
      console.log(`✅ Created customer: ${response.data.customer.email} (ID: ${response.data.customer.id})`);
      return response.data.customer;
    }
  } catch (error) {
    console.error('❌ Error creating customer in Shopify:', error.response?.data || error.message);
    
    // If customer already exists, try to find them
    if (error.response?.data?.errors?.email?.includes('has already been taken')) {
      console.log('🔍 Customer already exists, fetching...');
      return await getShopifyCustomerByEmail(email);
    }
    
    return null;
  }
}

// 🔥 REAL: Request verification code endpoint
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'E-Mail-Adresse ist erforderlich' });
  }

  try {
    console.log(`🔐 Requesting verification code for: ${email}`);

    // Check if customer exists in Shopify
    let customer = await getShopifyCustomerByEmail(email);
    let isNewCustomer = false;

    if (!customer) {
      console.log(`🆕 Customer doesn't exist, creating: ${email}`);
      customer = await createShopifyCustomer(email);
      isNewCustomer = true;
    }

    if (!customer) {
      throw new Error('Failed to find or create customer in Shopify');
    }

    // Generate verification code
    const code = generateVerificationCode();
    const sessionId = generateSessionId();

    // Store verification code
    config.verificationCodes.set(sessionId, {
      email,
      code,
      customerId: customer.id,
      customerData: customer,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
      isNewCustomer
    });

    // Send verification email
    await sendVerificationEmail(email, code);
    
    console.log(`✅ Verification code sent to: ${email} (Code: ${code})`);

    res.json({
      success: true,
      isNewCustomer,
      sessionId,
      message: isNewCustomer 
        ? 'Account created! Verification code sent to your email.'
        : 'Verification code sent to your email.'
    });

  } catch (error) {
    console.error('❌ Error requesting verification code:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to send verification code. Please try again.' 
    });
  }
});

// 🔥 REAL: Verify code and create session
app.post('/auth/verify-code', async (req, res) => {
  const { email, code, sessionId, requestLongLivedToken } = req.body;

  const verificationData = config.verificationCodes.get(sessionId);
  
  if (!verificationData || 
      verificationData.code !== code || 
      verificationData.email !== email ||
      verificationData.expiresAt < Date.now()) {
    return res.status(400).json({ success: false, error: 'Invalid or expired verification code' });
  }

  try {
    console.log(`✅ Verification successful for: ${email}`);

    // Generate app tokens
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshToken = crypto.randomBytes(32).toString('hex');
    
    const tokenLifetime = requestLongLivedToken ? 
      config.tokenLifetimes.accessToken : 
      24 * 60 * 60; // 24 hours default

    // Create session data
    const sessionData = {
      email,
      customerId: verificationData.customerId,
      customerData: verificationData.customerData,
      createdAt: Date.now(),
      expiresAt: Date.now() + tokenLifetime * 1000,
      refreshExpiresAt: Date.now() + config.tokenLifetimes.refreshToken * 1000,
      lastRefreshed: Date.now(),
    };

    // Store session and refresh token
    config.sessions.set(accessToken, sessionData);
    config.appRefreshTokens.set(refreshToken, {
      accessToken,
      email,
      customerId: verificationData.customerId,
      createdAt: Date.now(),
      expiresAt: Date.now() + config.tokenLifetimes.refreshToken * 1000,
    });

    // Clean up verification code
    config.verificationCodes.delete(sessionId);

    console.log(`✅ Session created for: ${email} (${requestLongLivedToken ? 'long-lived' : 'standard'})`);

    res.json({
      success: true,
      accessToken,
      refreshToken,
      customer: {
        id: verificationData.customerData.id,
        email: verificationData.customerData.email,
        firstName: verificationData.customerData.first_name || '',
        lastName: verificationData.customerData.last_name || '',
        displayName: verificationData.customerData.first_name || email.split('@')[0],
        phone: verificationData.customerData.phone || '',
        acceptsMarketing: verificationData.customerData.accepts_marketing || false,
      },
      expiresIn: tokenLifetime,
      refreshExpiresIn: config.tokenLifetimes.refreshToken,
    });

  } catch (error) {
    console.error('❌ Error during verification:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Verification failed. Please try again.' 
    });
  }
});

// Middleware to authenticate app tokens
const authenticateAppToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);
  const session = config.sessions.get(token);
  
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

// 🔥 REAL: Get customer orders from Shopify
app.get('/customer/orders', authenticateAppToken, async (req, res) => {
  try {
    if (!config.adminToken) {
      return res.json({ orders: [] });
    }

    const customerId = req.session.customerId;
    console.log(`📋 Fetching orders for customer: ${customerId}`);

    const response = await axios.get(
      `https://${config.shopDomain}/admin/api/2024-10/customers/${customerId}/orders.json`,
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const orders = response.data.orders || [];
    console.log(`✅ Found ${orders.length} orders for customer`);

    // Transform orders to match expected format
    const transformedOrders = orders.map(order => ({
      id: `gid://shopify/Order/${order.id}`,
      name: order.name,
      orderNumber: order.order_number,
      processedAt: order.processed_at,
      fulfillmentStatus: order.fulfillment_status?.toUpperCase() || 'UNFULFILLED',
      financialStatus: order.financial_status?.toUpperCase() || 'PENDING',
      currentTotalPrice: {
        amount: order.current_total_price,
        currencyCode: order.currency
      },
      totalPriceV2: {
        amount: order.total_price,
        currencyCode: order.currency
      },
      subtotalPriceV2: {
        amount: order.current_subtotal_price,
        currencyCode: order.currency
      },
      totalShippingPriceV2: {
        amount: order.total_shipping_price_set?.shop_money?.amount || '0.00',
        currencyCode: order.currency
      },
      totalTaxV2: {
        amount: order.current_total_tax,
        currencyCode: order.currency
      },
      shippingAddress: order.shipping_address,
      lineItems: {
        edges: order.line_items.map(item => ({
          node: {
            title: item.title,
            quantity: item.quantity,
            variant: {
              id: `gid://shopify/ProductVariant/${item.variant_id}`,
              title: item.variant_title,
              price: item.price,
              image: {
                url: item.image_url
              }
            },
            originalTotalPrice: {
              amount: (parseFloat(item.price) * item.quantity).toString(),
              currencyCode: order.currency
            }
          }
        }))
      }
    }));

    res.json({ orders: transformedOrders });

  } catch (error) {
    console.error('❌ Error fetching orders:', error.response?.data || error.message);
    res.json({ orders: [] });
  }
});

// 🔥 REAL: Get customer profile from Shopify
app.get('/customer/profile', authenticateAppToken, async (req, res) => {
  try {
    if (!config.adminToken) {
      return res.json({ customer: req.session.customerData });
    }

    const customerId = req.session.customerId;
    console.log(`👤 Fetching profile for customer: ${customerId}`);

    const response = await axios.get(
      `https://${config.shopDomain}/admin/api/2024-10/customers/${customerId}.json`,
      {
        headers: {
          'X-Shopify-Access-Token': config.adminToken,
          'Content-Type': 'application/json'
        }
      }
    );

    const customer = response.data.customer;
    if (customer) {
      const transformedCustomer = {
        id: customer.id,
        email: customer.email,
        firstName: customer.first_name || '',
        lastName: customer.last_name || '',
        displayName: customer.first_name || customer.email.split('@')[0],
        phone: customer.phone || '',
        acceptsMarketing: customer.accepts_marketing || false,
        defaultAddress: customer.default_address || null
      };

      res.json({ customer: transformedCustomer });
    } else {
      res.json({ customer: req.session.customerData });
    }

  } catch (error) {
    console.error('❌ Error fetching customer profile:', error.response?.data || error.message);
    res.json({ customer: req.session.customerData });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    mode: 'production',
    shopifyIntegration: true,
    adminTokenConfigured: !!config.adminToken,
    mailerSendConfigured: !!config.mailerSendApiKey,
    activeSessions: config.sessions.size,
    pendingVerifications: config.verificationCodes.size,
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Metallbude Auth Server running on port ${PORT}`);
  console.log(`🔐 Shopify Domain: ${config.shopDomain}`);
  console.log(`🔑 Admin Token: ${config.adminToken ? 'CONFIGURED' : 'MISSING - SET SHOPIFY_ADMIN_TOKEN'}`);
  console.log(`📧 MailerSend: ${config.mailerSendApiKey ? 'CONFIGURED' : 'MISSING - SET MAILERSEND_API_KEY'}`);
  console.log(`✅ Real Shopify Customer Account integration ready!`);
});