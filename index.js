import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';

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

// Email configuration
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const EMAIL_SERVICE = process.env.EMAIL_SERVICE || 'gmail';

// Create email transporter
const transporter = nodemailer.createTransport({
  service: EMAIL_SERVICE,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

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
          }
        }
      } catch (error) {
        console.error('Error checking customer:', error);
      }
    }
    
    // Send verification email
    try {
      await sendVerificationEmail(email, verificationCode, isNewCustomer);
      console.log(`Verification email sent to ${email}`);
    } catch (emailError) {
      console.error('Error sending email:', emailError);
      return res.status(500).json({ 
        success: false, 
        error: `Fehler beim Senden der E-Mail: ${emailError.message}` 
      });
    }
    
    // Return success with session ID
    res.json({ 
      success: true,
      isNewCustomer: isNewCustomer,
      sessionId: sessionId
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

// Helper function to send verification email
async function sendVerificationEmail(email, code, isNewCustomer) {
  const mailOptions = {
    from: EMAIL_USER,
    to: email,
    subject: 'Dein Anmeldecode für Metallbude',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 5px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <img src="https://metallbude.com/wp-content/uploads/2023/03/metallbude-logo.png" alt="Metallbude Logo" style="max-width: 200px;">
        </div>
        
        <h2 style="color: #333; text-align: center;">Dein Anmeldecode</h2>
        
        <p style="color: #666; font-size: 16px; line-height: 1.5;">
          ${isNewCustomer ? 'Willkommen bei Metallbude! Wir haben ein Konto für dich erstellt.' : 'Willkommen zurück bei Metallbude!'}
        </p>
        
        <p style="color: #666; font-size: 16px; line-height: 1.5;">
          Hier ist dein Anmeldecode:
        </p>
        
        <div style="background-color: #f4f4f4; padding: 15px; font-size: 24px; text-align: center; letter-spacing: 5px; font-weight: bold; margin: 20px 0; border-radius: 5px;">
          ${code}
        </div>
        
        <p style="color: #666; font-size: 16px; line-height: 1.5;">
          Dieser Code ist 15 Minuten gültig.
        </p>
        
        <p style="color: #666; font-size: 14px; margin-top: 30px; text-align: center;">
          Falls du diese E-Mail nicht angefordert hast, kannst du sie ignorieren.
        </p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eaeaea; text-align: center; color: #999; font-size: 12px;">
          &copy; ${new Date().getFullYear()} Metallbude. Alle Rechte vorbehalten.
        </div>
      </div>
    `
  };

  return transporter.sendMail(mailOptions);
}

app.listen(PORT, () => {
  console.log(`✅ Backend is live on port ${PORT}`);
  console.log(`Email configuration: ${EMAIL_USER ? 'Set' : 'Not set'}`);
});
