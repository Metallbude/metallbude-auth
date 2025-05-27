require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const { URL } = require('url');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Enable CORS for all origins
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuration from environment variables
const config = {
  shopDomain: process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com',
  storefrontToken: process.env.SHOPIFY_STOREFRONT_TOKEN,
  apiUrl: process.env.SHOPIFY_API_URL || 'https://metallbude-de.myshopify.com/api/2023-04/graphql.json',
  mailerSendApiKey: process.env.MAILERSEND_API_KEY,
  // In-memory storage for verification codes and sessions
  verificationCodes: new Map(),
  sessions: new Map()
};

// Helper function to generate random code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
}

// Helper function to generate session ID
function generateSessionId() {
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
    // Fallback to console log
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
    // Check if customer exists
    const checkCustomerQuery = `
      query checkCustomer($email: String!) {
        customers(first: 1, query: $email) {
          edges {
            node {
              id
              email
            }
          }
        }
      }
    `;

    let isNewCustomer = false;
    
    // Note: This query might not work with Storefront API
    // You might need to handle customer creation differently
    
    // Generate verification code
    const code = generateVerificationCode();
    const sessionId = generateSessionId();
    
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
    // For existing customers, we need to create a customer access token
    // Since we're using one-time codes, we'll need to use a different approach
    
    // Option 1: Use a master password for all one-time code logins
    // Option 2: Create temporary passwords
    // Option 3: Use a custom authentication solution
    
    // For this example, we'll create a temporary password
    const tempPassword = crypto.randomBytes(32).toString('hex');
    
    let customerAccessToken = null;
    let customer = null;

    if (verificationData.isNewCustomer) {
      // Create new customer
      const createCustomerMutation = `
        mutation customerCreate($input: CustomerCreateInput!) {
          customerCreate(input: $input) {
            customer {
              id
              email
              firstName
              lastName
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
          password: tempPassword,
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

      customer = createResult.data?.customerCreate?.customer;
    }

    // Create customer access token
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

    // For existing customers, you might need to implement a different strategy
    // This is a limitation of Shopify's customer authentication system
    
    // As a workaround, you could:
    // 1. Use Shopify's passwordless authentication (if available)
    // 2. Implement a proxy authentication system
    // 3. Use Shopify's multipass (requires Shopify Plus)
    
    // For now, let's create a mock token for demonstration
    customerAccessToken = crypto.randomBytes(32).toString('hex');
    
    // In a real implementation, you would get the actual customer data
    if (!customer) {
      customer = {
        id: `gid://shopify/Customer/${crypto.randomBytes(8).toString('hex')}`,
        email: email,
        firstName: '',
        lastName: ''
      };
    }

    // Store session
    config.sessions.set(customerAccessToken, {
      email,
      customer,
      createdAt: Date.now()
    });

    // Clean up verification code
    config.verificationCodes.delete(sessionId);

    console.log(`Successful login for ${email}`);

    res.json({
      success: true,
      accessToken: customerAccessToken,
      customer: customer
    });

  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Fehler bei der Verifizierung' 
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