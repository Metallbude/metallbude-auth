require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
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

// Configuration from environment variables
const config = {
  shopDomain: process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com',
  storefrontToken: process.env.SHOPIFY_STOREFRONT_TOKEN,
  adminApiToken: process.env.SHOPIFY_ADMIN_API_TOKEN, // You'll need this for creating customers
  apiUrl: process.env.SHOPIFY_API_URL || 'https://metallbude-de.myshopify.com/api/2024-01/graphql.json',
  adminApiUrl: `https://${process.env.SHOPIFY_SHOP_DOMAIN}/admin/api/2024-01/graphql.json`,
  mailerSendApiKey: process.env.MAILERSEND_API_KEY,
  // In-memory storage for verification codes and sessions
  verificationCodes: new Map(),
  sessions: new Map(),
  customerPasswords: new Map() // Store generated passwords for customers
};

// Helper function to generate random code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
}

// Helper function to generate session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to generate secure password
function generateSecurePassword() {
  return crypto.randomBytes(32).toString('hex');
}

// Send email using MailerSend
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
        to: [{
          email: email
        }],
        subject: 'Ihr Anmeldecode für Metallbude',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Ihr Anmeldecode</h2>
            <p>Geben Sie diesen Code in der App ein:</p>
            <h1 style="font-size: 32px; letter-spacing: 5px; color: #333;">${code}</h1>
            <p>Dieser Code ist 10 Minuten gültig.</p>
            <p>Wenn Sie diesen Code nicht angefordert haben, ignorieren Sie diese E-Mail bitte.</p>
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

// GraphQL client for Shopify Storefront API
async function shopifyStorefrontQuery(query, variables = {}) {
  try {
    const response = await axios.post(
      config.apiUrl,
      { query, variables },
      {
        headers: {
          'X-Shopify-Storefront-Access-Token': config.storefrontToken,
          'Content-Type': 'application/json',
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Storefront API error:', error.response?.data || error.message);
    throw error;
  }
}

// Request one-time code endpoint
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ 
      success: false, 
      error: 'E-Mail-Adresse ist erforderlich' 
    });
  }

  try {
    // Generate verification code
    const code = generateVerificationCode();
    const sessionId = generateSessionId();
    
    // Check if we have a stored password for this customer
    let customerPassword = config.customerPasswords.get(email);
    let isNewCustomer = false;
    
    if (!customerPassword) {
      // Try to authenticate with a dummy password to check if customer exists
      const checkCustomerMutation = `
        mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
          customerAccessTokenCreate(input: $input) {
            customerAccessToken {
              accessToken
            }
            customerUserErrors {
              code
              field
              message
            }
          }
        }
      `;

      const checkResult = await shopifyStorefrontQuery(checkCustomerMutation, {
        input: {
          email: email,
          password: 'dummy_check_password'
        }
      });

      // If the error is UNIDENTIFIED_CUSTOMER, the customer doesn't exist
      const errors = checkResult.data?.customerAccessTokenCreate?.customerUserErrors || [];
      isNewCustomer = errors.some(err => err.code === 'UNIDENTIFIED_CUSTOMER');
      
      if (!isNewCustomer) {
        // Customer exists but we don't have their password stored
        // Generate a new password for them
        customerPassword = generateSecurePassword();
        config.customerPasswords.set(email, customerPassword);
      }
    }
    
    // Store code with expiration (10 minutes)
    config.verificationCodes.set(sessionId, {
      email,
      code,
      isNewCustomer,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
    });

    // Clean up expired codes
    setTimeout(() => {
      config.verificationCodes.delete(sessionId);
    }, 10 * 60 * 1000);

    // Send verification email
    await sendVerificationEmail(email, code);

    console.log(`Generated verification code for ${email}: ${code}`);

    res.json({
      success: true,
      isNewCustomer,
      sessionId,
      message: 'Verifizierungscode wurde gesendet',
      // Only include debug code in development
      ...(process.env.NODE_ENV !== 'production' && { debug: { code } })
    });

  } catch (error) {
    console.error('Request code error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Fehler beim Senden des Codes' 
    });
  }
});

// Verify code endpoint
app.post('/auth/verify-code', async (req, res) => {
  const { email, code, sessionId } = req.body;

  if (!email || !code || !sessionId) {
    return res.status(400).json({ 
      success: false, 
      error: 'E-Mail, Code und Session ID sind erforderlich' 
    });
  }

  // Get stored verification data
  const verificationData = config.verificationCodes.get(sessionId);

  if (!verificationData) {
    return res.status(400).json({ 
      success: false, 
      error: 'Ungültige oder abgelaufene Sitzung' 
    });
  }

  // Check if code has expired
  if (verificationData.expiresAt < Date.now()) {
    config.verificationCodes.delete(sessionId);
    return res.status(400).json({ 
      success: false, 
      error: 'Verifizierungscode ist abgelaufen' 
    });
  }

  // Verify email matches
  if (verificationData.email !== email) {
    return res.status(400).json({ 
      success: false, 
      error: 'E-Mail stimmt nicht überein' 
    });
  }

  // Verify code
  if (verificationData.code !== code) {
    return res.status(400).json({ 
      success: false, 
      error: 'Ungültiger Verifizierungscode' 
    });
  }

  try {
    let customerAccessToken = null;
    let customerData = null;
    
    // Get or generate password for this customer
    let customerPassword = config.customerPasswords.get(email);
    if (!customerPassword) {
      customerPassword = generateSecurePassword();
      config.customerPasswords.set(email, customerPassword);
    }

    if (verificationData.isNewCustomer) {
      // Create new customer with the generated password
      const createCustomerMutation = `
        mutation customerCreate($input: CustomerCreateInput!) {
          customerCreate(input: $input) {
            customer {
              id
              email
              firstName
              lastName
              displayName
            }
            customerAccessToken {
              accessToken
              expiresAt
            }
            customerUserErrors {
              field
              message
              code
            }
          }
        }
      `;

      const createResult = await shopifyStorefrontQuery(createCustomerMutation, {
        input: {
          email: email,
          password: customerPassword,
          acceptsMarketing: false
        }
      });

      if (createResult.data?.customerCreate?.customerUserErrors?.length > 0) {
        const error = createResult.data.customerCreate.customerUserErrors[0];
        return res.status(400).json({ 
          success: false, 
          error: error.message 
        });
      }

      customerData = createResult.data?.customerCreate?.customer;
      customerAccessToken = createResult.data?.customerCreate?.customerAccessToken?.accessToken;
      
    } else {
      // Existing customer - try to authenticate
      const tokenMutation = `
        mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
          customerAccessTokenCreate(input: $input) {
            customerAccessToken {
              accessToken
              expiresAt
            }
            customerUserErrors {
              field
              message
              code
            }
          }
        }
      `;

      const tokenResult = await shopifyStorefrontQuery(tokenMutation, {
        input: {
          email: email,
          password: customerPassword
        }
      });

      if (tokenResult.data?.customerAccessTokenCreate?.customerUserErrors?.length > 0) {
        // Password might have changed, we need admin API to reset it
        // For now, return an error
        return res.status(400).json({ 
          success: false, 
          error: 'Authentifizierung fehlgeschlagen. Bitte kontaktieren Sie den Support.' 
        });
      }

      customerAccessToken = tokenResult.data?.customerAccessTokenCreate?.customerAccessToken?.accessToken;

      // Fetch customer details
      if (customerAccessToken) {
        const customerQuery = `
          query getCustomer($customerAccessToken: String!) {
            customer(customerAccessToken: $customerAccessToken) {
              id
              email
              firstName
              lastName
              displayName
            }
          }
        `;

        const customerResult = await shopifyStorefrontQuery(customerQuery, {
          customerAccessToken: customerAccessToken
        });

        customerData = customerResult.data?.customer;
      }
    }

    if (!customerAccessToken || !customerData) {
      throw new Error('Fehler beim Erstellen des Kundenzugangs');
    }

    // Store session with real Shopify data
    config.sessions.set(customerAccessToken, {
      email,
      customer: customerData,
      createdAt: Date.now()
    });

    // Clean up verification code
    config.verificationCodes.delete(sessionId);

    console.log(`Successful login for ${email} with Shopify ID: ${customerData.id}`);

    res.json({
      success: true,
      accessToken: customerAccessToken,
      customer: customerData
    });

  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Fehler bei der Verifizierung' 
    });
  }
});

// Validate token endpoint
app.post('/auth/validate-token', async (req, res) => {
  const { accessToken } = req.body;

  if (!accessToken) {
    return res.status(400).json({ 
      success: false, 
      error: 'Access token is required' 
    });
  }

  try {
    const customerQuery = `
      query validateCustomer($customerAccessToken: String!) {
        customer(customerAccessToken: $customerAccessToken) {
          id
          email
        }
      }
    `;

    const result = await shopifyStorefrontQuery(customerQuery, {
      customerAccessToken: accessToken
    });

    if (result.data?.customer) {
      res.json({
        success: true,
        valid: true,
        customer: result.data.customer
      });
    } else {
      res.json({
        success: true,
        valid: false
      });
    }
  } catch (error) {
    console.error('Token validation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to validate token' 
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: {
      shopDomain: config.shopDomain,
      hasStorefrontToken: !!config.storefrontToken,
      hasMailerSendKey: !!config.mailerSendApiKey
    }
  });
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Shopify Customer Auth Server running on port ${PORT}`);
  console.log(`Shop Domain: ${config.shopDomain}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Clean up old sessions and codes periodically
setInterval(() => {
  const now = Date.now();
  
  // Clean expired verification codes
  for (const [sessionId, data] of config.verificationCodes.entries()) {
    if (data.expiresAt < now) {
      config.verificationCodes.delete(sessionId);
    }
  }
  
  // Clean old sessions (24 hours)
  const sessionTimeout = 24 * 60 * 60 * 1000;
  for (const [token, session] of config.sessions.entries()) {
    if (now - session.createdAt > sessionTimeout) {
      config.sessions.delete(token);
    }
  }
}, 60 * 60 * 1000); // Every hour