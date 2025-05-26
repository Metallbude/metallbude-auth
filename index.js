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
const API_VERSION = '2023-04';

// Klaviyo configuration
const KLAVIYO_PRIVATE_KEY = process.env.KLAVIYO_PRIVATE_KEY;
console.log(`Klaviyo API Key: ${KLAVIYO_PRIVATE_KEY ? 'Set' : 'Not set'}`);

// Store for verification codes and sessions
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
    
    if (ADMIN_API_TOKEN) {
      // First, check if customer exists
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
            customer = customers[0].node;
          }
        }
      } catch (error) {
        console.error('Error getting customer:', error);
      }
      
      // If customer doesn't exist, create one
      if (!customer) {
        try {
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
                  acceptsMarketing: true,
                },
              },
            }),
          });

          const createData = await createResponse.json();
          
          if (!createData.errors && !createData.data?.customerCreate?.userErrors?.length) {
            customer = createData.data?.customerCreate?.customer;
          }
        } catch (error) {
          console.error('Error creating customer:', error);
        }
      }
    }
    
    // If we still don't have a customer, create a placeholder
    if (!customer) {
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
      expires: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days expiration
    };
    
    // Clean up the session
    delete pendingSessions[sessionId];
    
    // Return success with customer data and token
    res.json({
      success: true,
      accessToken: accessToken,
      customer: customer
    });
  } catch (error) {
    console.error('Error in verify-code endpoint:', error);
    res.status(500).json({ success: false, error: error.message });
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

// Helper function to trigger Klaviyo Flow event to send the verification code
async function sendVerificationEmail(email, code, isNewCustomer, firstName = '', lastName = '') {
  if (!KLAVIYO_PRIVATE_KEY) {
    console.log('Klaviyo API Key not set. SIMULATED EMAIL:');
    console.log('To:', email);
    console.log('Code:', code);
    return true;
  }

  try {
    // Enhanced payload with multiple ways to access the verification code
    const klaviyoPayload = {
      data: {
        type: 'event',
        attributes: {
          profile: {
            email,
            first_name: firstName,
            last_name: lastName
          },
          metric: {
            name: 'one_time_code_requested'
          },
          properties: {
            verification_code: code,
            code: code, // Alternative simpler property name
            verificationCode: code, // Camel case alternative
            otp: code, // Common abbreviation for one-time password
            welcome_message: isNewCustomer
              ? 'Willkommen bei Metallbude! Wir haben ein Konto für dich erstellt.'
              : 'Willkommen zurück bei Metallbude!',
            is_new_customer: isNewCustomer, // Add this flag for template logic
            formatted_code: code.split('').join(' ') // Spaced format to avoid filtering
          }
        }
      }
    };
    
    console.log('📦 Klaviyo event payload:', JSON.stringify(klaviyoPayload, null, 2));
    
    // Make the API request with improved error handling
    const response = await fetch('https://a.klaviyo.com/api/events/', {
      method: 'POST',
      headers: {
        'Authorization': `Klaviyo-API-Key ${KLAVIYO_PRIVATE_KEY}`,
        'Content-Type': 'application/json',
        'revision': '2023-02-22',
        'Accept': 'application/json'
      },
      body: JSON.stringify(klaviyoPayload)
    });

    // Enhanced error handling with detailed response logging
    if (!response.ok) {
      let errorDetails;
      try {
        errorDetails = await response.json();
      } catch (e) {
        errorDetails = await response.text();
      }
      
      console.error('❌ Klaviyo API error details:', JSON.stringify(errorDetails, null, 2));
      throw new Error(`Klaviyo API error: ${response.status} ${response.statusText}`);
    }

    // Log successful response data
    try {
      const responseData = await response.json();
      console.log('✅ Klaviyo API response:', JSON.stringify(responseData, null, 2));
    } catch (e) {
      console.log('✅ Klaviyo request successful (no JSON response)');
    }

    console.log(`📬 Klaviyo one_time_code_requested event triggered for ${email} with code ${code}`);
    return true;
  } catch (error) {
    console.error('❌ Klaviyo API error:', error);
    return false;
  }
}

// Optional: Add a fallback email sender function
async function sendFallbackEmail(email, code) {
  console.log('⚠️ Using fallback email method for', email);
  // Implement your fallback email sending logic here
  // This could use a different service like SendGrid, AWS SES, etc.
  return true;
}

app.listen(PORT, () => {
  console.log(`✅ Backend is live on port ${PORT}`);
  console.log(`Klaviyo API Key: ${KLAVIYO_PRIVATE_KEY ? 'Set' : 'Not set'}`);
});
