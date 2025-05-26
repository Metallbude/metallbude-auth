import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// Shopify API configuration
const SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com';
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN || '8af29dd8b68e0bcfe5f9f99a86ebf1a3';
const ADMIN_API_TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN;
const API_VERSION = '2023-10'; // Updated to latest version

// MailerSend configuration
const MAILERSEND_API_KEY = process.env.MAILERSEND_API_KEY;
console.log(`MailerSend API Key: ${MAILERSEND_API_KEY ? 'Set' : 'Not set'}`);

// Store for verification codes and sessions
const authCodes = {};
const pendingSessions = {};
const verifiedCustomers = {};

// Request one-time code endpoint
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'Email ist erforderlich' });
  }

  try {
    // Generate a session ID for this verification attempt
    const sessionId = uuidv4();
    
    // Generate a verification code
    const verificationCode = generateVerificationCode();
    
    // Store session data
    pendingSessions[sessionId] = {
      email,
      expires: Date.now() + 15 * 60 * 1000, // 15 minutes expiration
      verificationCode: verificationCode
    };
    
    console.log(`Generated verification code for ${email}: ${verificationCode}`);
    
    // Check if customer exists in Shopify
    let isNewCustomer = true;
    let firstName = '';
    let lastName = '';
    
    if (ADMIN_API_TOKEN) {
      try {
        const customerResponse = await fetch(`https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': ADMIN_API_TOKEN,
          },
          body: JSON.stringify({
            query: `
              query GetCustomerByEmail($query: String!) {
                customers(first: 1, query: $query) {
                  edges {
                    node {
                      id
                      email
                      firstName
                      lastName
                    }
                  }
                }
              }
            `,
            variables: {
              query: `email:${email}`,
            },
          }),
        });

        const customerData = await customerResponse.json();
        
        if (!customerData.errors) {
          const customers = customerData.data?.customers?.edges || [];
          if (customers.length > 0) {
            isNewCustomer = false;
            firstName = customers[0].node.firstName || '';
            lastName = customers[0].node.lastName || '';
          }
        }
      } catch (error) {
        console.error('Error checking customer:', error);
      }
    }
    
    // Send verification email
    try {
      await sendVerificationEmail(email, verificationCode, isNewCustomer, firstName, lastName);
      console.log(`Verification email sent to ${email}`);
    } catch (emailError) {
      console.error('Error sending email:', emailError);
      // Continue anyway, but log the error
    }
    
    // Return success with session ID and verification code for testing
    res.json({ 
      success: true,
      isNewCustomer: isNewCustomer,
      sessionId: sessionId,
      // Include the code in the response for testing
      verificationCode: verificationCode
    });
  } catch (error) {
    console.error('Error in request-code endpoint:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify code endpoint
app.post('/auth/verify-code', async (req, res) => {
  const { email, code, sessionId } = req.body;

  if (!email || !code || !sessionId) {
    return res.status(400).json({ success: false, error: 'Email, Code und Session-ID sind erforderlich' });
  }

  try {
    // Check if session exists
    const session = pendingSessions[sessionId];
    if (!session) {
      return res.status(400).json({ success: false, error: 'Ungültige oder abgelaufene Sitzung' });
    }
    
    // Check if session is expired
    if (Date.now() > session.expires) {
      delete pendingSessions[sessionId];
      return res.status(400).json({ success: false, error: 'Sitzung abgelaufen' });
    }
    
    // Check if email matches
    if (session.email !== email) {
      return res.status(400).json({ success: false, error: 'E-Mail stimmt nicht mit der Sitzung überein' });
    }
    
    // Check if code matches
    if (session.verificationCode !== code) {
      return res.status(400).json({ success: false, error: 'Ungültiger Code' });
    }
    
    // Code is valid - create or get customer
    let customer = null;
    let shopifyCustomerAccessToken = null;
    let isNewCustomer = true;
    
    if (ADMIN_API_TOKEN) {
      // First, check if customer exists
      try {
        console.log(`Checking if customer exists for email: ${email}`);
        const customerResponse = await fetch(`https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': ADMIN_API_TOKEN,
          },
          body: JSON.stringify({
            query: `
              query GetCustomerByEmail($query: String!) {
                customers(first: 1, query: $query) {
                  edges {
                    node {
                      id
                      firstName
                      lastName
                      email
                      phone
                      defaultAddress {
                        id
                        address1
                        city
                        country
                        zip
                      }
                      addresses {
                        id
                        address1
                        address2
                        city
                        country
                        firstName
                        lastName
                        phone
                        zip
                      }
                      orders(first: 5) {
                        edges {
                          node {
                            id
                            name
                            processedAt
                            totalPriceSet {
                              shopMoney {
                                amount
                                currencyCode
                              }
                            }
                            fulfillmentStatus
                          }
                        }
                      }
                    }
                  }
                }
              }
            `,
            variables: {
              query: `email:${email}`,
            },
          }),
        });

        const customerData = await customerResponse.json();
        console.log('Customer lookup response:', JSON.stringify(customerData, null, 2));
        
        if (!customerData.errors) {
          const customers = customerData.data?.customers?.edges || [];
          if (customers.length > 0) {
            customer = customers[0].node;
            isNewCustomer = false;
            console.log(`Found existing customer with ID: ${customer.id}`);
            
            // Generate a Shopify customer access token
            try {
              console.log(`Attempting to generate Shopify customer access token for ${email}...`);
              
              // For existing customers, we need to reset their password first
              const resetResponse = await fetch(`https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Shopify-Access-Token': ADMIN_API_TOKEN,
                },
                body: JSON.stringify({
                  query: `
                    mutation customerResetByUrl($id: ID!, $input: CustomerResetInput!) {
                      customerResetByUrl(id: $id, input: $input) {
                        customer {
                          id
                        }
                        customerUserErrors {
                          code
                          field
                          message
                        }
                      }
                    }
                  `,
                  variables: {
                    id: customer.id,
                    input: {
                      password: generateTemporaryPassword(email),
                      resetUrl: `https://${SHOP_DOMAIN}/account/reset`
                    }
                  }
                }),
              });
              
              const resetData = await resetResponse.json();
              console.log('Password reset response:', JSON.stringify(resetData, null, 2));
              
              // Now try to get the access token
              const tempPassword = generateTemporaryPassword(email);
              console.log(`Generated temporary password for ${email}`);
              
              const tokenResponse = await fetch(`https://${SHOP_DOMAIN}/api/${API_VERSION}/graphql.json`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Shopify-Storefront-Access-Token': STOREFRONT_TOKEN,
                },
                body: JSON.stringify({
                  query: `
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
                  `,
                  variables: {
                    input: {
                      email: email,
                      password: tempPassword
                    }
                  }
                }),
              });
              
              const tokenData = await tokenResponse.json();
              console.log('Shopify token response:', JSON.stringify(tokenData, null, 2));
              
              if (tokenData.data?.customerAccessTokenCreate?.customerAccessToken?.accessToken) {
                shopifyCustomerAccessToken = tokenData.data.customerAccessTokenCreate.customerAccessToken.accessToken;
                console.log(`✅ Successfully generated Shopify customer access token for ${email}`);
              } else if (tokenData.data?.customerAccessTokenCreate?.customerUserErrors) {
                console.error('Error generating token:', tokenData.data.customerAccessTokenCreate.customerUserErrors);
              }
            } catch (tokenError) {
              console.error('Error generating customer access token:', tokenError);
            }
          }
        }
      } catch (error) {
        console.error('Error getting customer:', error);
      }
      
      // If customer doesn't exist, create one
      if (!customer) {
        try {
          console.log(`Creating new customer for email: ${email}`);
          const tempPassword = generateTemporaryPassword(email);
          
          const createResponse = await fetch(`https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Shopify-Access-Token': ADMIN_API_TOKEN,
            },
            body: JSON.stringify({
              query: `
                mutation customerCreate($input: CustomerInput!) {
                  customerCreate(input: $input) {
                    customer {
                      id
                      firstName
                      lastName
                      email
                      phone
                    }
                    userErrors {
                      field
                      message
                    }
                  }
                }
              `,
              variables: {
                input: {
                  email: email,
                  password: tempPassword,
                  acceptsMarketing: true,
                },
              },
            }),
          });

          const createData = await createResponse.json();
          console.log('Customer creation response:', JSON.stringify(createData, null, 2));
          
          if (!createData.errors && !createData.data?.customerCreate?.userErrors?.length) {
            customer = createData.data?.customerCreate?.customer;
            console.log(`Created new customer with ID: ${customer.id}`);
            
            // Generate a Shopify customer access token for the new customer
            try {
              console.log(`Attempting to generate Shopify customer access token for new customer ${email}...`);
              
              const tokenResponse = await fetch(`https://${SHOP_DOMAIN}/api/${API_VERSION}/graphql.json`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Shopify-Storefront-Access-Token': STOREFRONT_TOKEN,
                },
                body: JSON.stringify({
                  query: `
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
                  `,
                  variables: {
                    input: {
                      email: email,
                      password: tempPassword
                    }
                  }
                }),
              });
              
              const tokenData = await tokenResponse.json();
              console.log('Shopify token response for new customer:', JSON.stringify(tokenData, null, 2));
              
              if (tokenData.data?.customerAccessTokenCreate?.customerAccessToken?.accessToken) {
                shopifyCustomerAccessToken = tokenData.data.customerAccessTokenCreate.customerAccessToken.accessToken;
                console.log(`✅ Successfully generated Shopify customer access token for new customer ${email}`);
              } else if (tokenData.data?.customerAccessTokenCreate?.customerUserErrors) {
                console.error('Error generating token for new customer:', tokenData.data.customerAccessTokenCreate.customerUserErrors);
              }
            } catch (tokenError) {
              console.error('Error generating customer access token for new customer:', tokenError);
            }
          } else {
            console.error('Error creating customer:', createData.data?.customerCreate?.userErrors || createData.errors);
          }
        } catch (error) {
          console.error('Error creating customer:', error);
        }
      }
    }
    
    // If we still don't have a customer, create a placeholder
    if (!customer) {
      console.log(`Creating placeholder customer for ${email} (no Shopify integration)`);
      customer = {
        id: `gid://shopify/Customer/${Date.now()}`,
        firstName: '',
        lastName: '',
        email: email,
        phone: null,
        defaultAddress: null
      };
    }
    
    // Generate an access token
    const accessToken = generateAccessToken();
    
    // Store the verified customer
    verifiedCustomers[accessToken] = {
      customer,
      shopifyCustomerAccessToken,
      expires: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days expiration
    };
    
    // Clean up the session
    delete pendingSessions[sessionId];
    
    // Return success with customer data and token
    res.json({
      success: true,
      accessToken: accessToken,
      shopifyCustomerAccessToken: shopifyCustomerAccessToken,
      customer: customer,
      isNewCustomer: isNewCustomer
    });
  } catch (error) {
    console.error('Error in verify-code endpoint:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get customer profile endpoint
app.get('/customer/profile', async (req, res) => {
  const accessToken = req.headers.authorization?.split(' ')[1];
  
  if (!accessToken) {
    return res.status(401).json({ success: false, error: 'Authorization token required' });
  }
  
  const verifiedCustomer = verifiedCustomers[accessToken];
  
  if (!verifiedCustomer) {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
  
  if (Date.now() > verifiedCustomer.expires) {
    delete verifiedCustomers[accessToken];
    return res.status(401).json({ success: false, error: 'Token expired' });
  }
  
  // Return the customer profile
  res.json({
    success: true,
    customer: verifiedCustomer.customer,
    shopifyCustomerAccessToken: verifiedCustomer.shopifyCustomerAccessToken
  });
});

// Get customer orders endpoint
app.get('/customer/orders', async (req, res) => {
  const accessToken = req.headers.authorization?.split(' ')[1];
  
  if (!accessToken) {
    return res.status(401).json({ success: false, error: 'Authorization token required' });
  }
  
  const verifiedCustomer = verifiedCustomers[accessToken];
  
  if (!verifiedCustomer) {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
  
  if (Date.now() > verifiedCustomer.expires) {
    delete verifiedCustomers[accessToken];
    return res.status(401).json({ success: false, error: 'Token expired' });
  }
  
  try {
    // Use the Shopify Admin API to get orders
    if (ADMIN_API_TOKEN) {
      const ordersResponse = await fetch(`https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': ADMIN_API_TOKEN,
        },
        body: JSON.stringify({
          query: `
            query getCustomerOrders($customerId: ID!) {
              customer(id: $customerId) {
                orders(first: 10) {
                  edges {
                    node {
                      id
                      name
                      orderNumber
                      processedAt
                      fulfillmentStatus
                      financialStatus
                      totalPriceSet {
                        shopMoney {
                          amount
                          currencyCode
                        }
                      }
                      lineItems(first: 10) {
                        edges {
                          node {
                            title
                            quantity
                            variant {
                              title
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
          `,
          variables: {
            customerId: verifiedCustomer.customer.id,
          },
        }),
      });

      const ordersData = await ordersResponse.json();
      
      if (ordersData.errors) {
        console.error('Shopify API errors:', ordersData.errors);
        return res.status(500).json({ success: false, error: 'Error fetching orders from Shopify' });
      }
      
      const orders = ordersData.data?.customer?.orders?.edges?.map(edge => edge.node) || [];
      
      return res.json({
        success: true,
        orders: orders
      });
    } else {
      return res.status(500).json({ success: false, error: 'Shopify Admin API token not configured' });
    }
  } catch (error) {
    console.error('Error fetching orders:', error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Helper function to generate a verification code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to generate an access token
function generateAccessToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to generate a temporary password for Shopify customers
function generateTemporaryPassword(email) {
  return crypto.createHash('sha256').update(email + Date.now().toString()).digest('hex').substring(0, 20);
}

// Helper function to send verification email using MailerSend
async function sendVerificationEmail(email, code, isNewCustomer, firstName = '', lastName = '') {
  if (!MAILERSEND_API_KEY) {
    console.log('MailerSend API Key not set. SIMULATED EMAIL:');
    console.log('To:', email);
    console.log('Code:', code);
    return true;
  }

  try {
    // Get the admin email from environment variables or use a default
    const adminEmail = process.env.ADMIN_EMAIL || email;
    
    // For trial accounts, always send to admin email but include the original recipient in the subject
    const recipientEmail = process.env.MAILERSEND_TRIAL_MODE === 'true' ? adminEmail : email;
    const recipientName = firstName ? `${firstName} ${lastName}`.trim() : email;
    
    // Create the email payload for MailerSend
    const mailerSendPayload = {
      from: {
        email: "noreply@metallbude.com", // Update with your verified domain
        name: "Metallbude"
      },
      to: [
        {
          email: recipientEmail,
          name: recipientName
        }
      ],
      subject: process.env.MAILERSEND_TRIAL_MODE === 'true' 
        ? `[TEST for ${email}] Dein Bestätigungscode für Metallbude` 
        : "Dein Bestätigungscode für Metallbude",
      template_id: "neqvygm1858g0p7w", // Your MailerSend template ID
      variables: [
        {
          email: recipientEmail,
          substitutions: [
            {
              var: "verification_code",
              value: code
            },
            {
              var: "welcome_message",
              value: isNewCustomer
                ? 'Willkommen bei Metallbude! Wir haben ein Konto für dich erstellt.'
                : 'Willkommen zurück bei Metallbude!'
            },
            {
              var: "first_name",
              value: firstName || ""
            }
          ]
        }
      ]
    };
    
    console.log('📦 MailerSend payload:', JSON.stringify(mailerSendPayload, null, 2));
    
    // Make the API request
    const response = await fetch('https://api.mailersend.com/v1/email', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${MAILERSEND_API_KEY}`,
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify(mailerSendPayload)
    });

    // Handle response
    if (!response.ok) {
      let errorDetails;
      try {
        errorDetails = await response.json();
      } catch (e) {
        errorDetails = await response.text();
      }
      
      console.error('❌ MailerSend API error details:', JSON.stringify(errorDetails, null, 2));
      
      // If we're in trial mode and still getting errors, fall back to simulation
      if (process.env.MAILERSEND_TRIAL_MODE === 'true') {
        console.log('⚠️ Falling back to simulated email in trial mode:');
        console.log('To:', email);
        console.log('Code:', code);
        return true;
      }
      
      throw new Error(`MailerSend API error: ${response.status} ${response.statusText}`);
    }

    // Log successful response
    let responseData = {};
    try {
      responseData = await response.json();
      console.log('✅ MailerSend API response:', JSON.stringify(responseData, null, 2));
    } catch (e) {
      console.log('✅ MailerSend response had no JSON body or malformed content.');
    }
    
    if (process.env.MAILERSEND_TRIAL_MODE === 'true') {
      console.log(`📬 TEST verification email sent to admin (${recipientEmail}) for ${email} with code ${code}`);
    } else {
      console.log(`📬 Verification email sent to ${email} with code ${code}`);
    }
    
    return true;
  } catch (error) {
    console.error('❌ MailerSend API error:', error);
    
    // In case of error, simulate email delivery
    console.log('⚠️ Falling back to simulated email:');
    console.log('To:', email);
    console.log('Code:', code);
    return true;
  }
}

// Add a health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Backend is live on port ${PORT}`);
  console.log(`MailerSend API Key: ${MAILERSEND_API_KEY ? 'Set' : 'Not set'}`);
});

// Function to verify code with Shopify (Shopify Account API)
async function verifyCodeWithShopify(email, code) {
  try {
    const response = await fetch('https://metallbude-de.myshopify.com/account/api/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Customer-Account-API-Version': '2023-07',
      },
      body: JSON.stringify({
        query: `
          mutation customerAccessTokenCreateWithEmailVerificationCode($email: String!, $emailVerificationCode: String!) {
            customerAccessTokenCreateWithEmailVerificationCode(email: $email, emailVerificationCode: $emailVerificationCode) {
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
        `,
        variables: {
          email,
          emailVerificationCode: code,
        }
      })
    });

    const result = await response.json();
    console.log("🔐 Shopify Login Response:", JSON.stringify(result, null, 2));

    if (result.data?.customerAccessTokenCreateWithEmailVerificationCode?.customerAccessToken) {
      return {
        success: true,
        accessToken: result.data.customerAccessTokenCreateWithEmailVerificationCode.customerAccessToken.accessToken,
        expiresAt: result.data.customerAccessTokenCreateWithEmailVerificationCode.customerAccessToken.expiresAt,
      };
    } else {
      return {
        success: false,
        errors: result.data?.customerAccessTokenCreateWithEmailVerificationCode?.customerUserErrors ?? [],
      };
    }
  } catch (err) {
    console.error('Error verifying code with Shopify:', err);
    return {
      success: false,
      error: 'Unexpected error while verifying with Shopify.'
    };
  }
}

// --- OIDC Authorization endpoint ---

app.get('/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, state, scope, code_challenge, code_challenge_method } = req.query;

  if (!redirect_uri || !client_id || !state || !response_type) {
    return res.status(400).send('Missing required parameters.');
  }

  const authCode = uuidv4();
  const email = 'rudolf.klause@metallbude.com'; // TODO: pull from session once real login exists
  authCodes[authCode] = { email };

  const redirectWithCode = `${redirect_uri}?code=${authCode}&state=${state}`;
  res.redirect(redirectWithCode);
});

app.post('/token', async (req, res) => {
  const { code, client_id, client_secret, redirect_uri, grant_type } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  if (!code || !client_id || !client_secret || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const session = authCodes[code];
  if (!session || session.expires < Date.now()) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  // Generate dummy tokens for now (replace with JWTs later if needed)
  const accessToken = crypto.randomBytes(32).toString('hex');
  const idToken = crypto.randomBytes(32).toString('hex');

  verifiedCustomers[accessToken] = {
    email: session.email,
    created: Date.now(),
  };

  delete authCodes[code]; // Code is single-use

  res.json({
    access_token: accessToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: 3600,
  });
});

// Userinfo endpoint (stub)
app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  const customer = verifiedCustomers[token];

  if (!customer) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  res.json({
    sub: customer.id,
    email: customer.email,
    email_verified: true,
  });
});

// Userinfo endpoint (stub)

// Logout endpoint
app.get('/logout', (req, res) => {
  res.send('Logged out');
});

// Discovery endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = `https://${req.headers.host}`;
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    end_session_endpoint: `${issuer}/logout`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
  });
});