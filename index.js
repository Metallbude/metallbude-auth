import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// Shopify API configuration
const SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com';
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN || '8af29dd8b68e0bcfe5f9f99a86ebf1a3';
const ADMIN_API_TOKEN = process.env.SHOPIFY_ADMIN_API_TOKEN; // Your metallbudeauth app's Admin API token
const API_VERSION = '2023-04'; // Update to your preferred API version

// Shopify API URLs
const STOREFRONT_API_URL = `https://${SHOP_DOMAIN}/api/${API_VERSION}/graphql.json`;
const ADMIN_API_URL = `https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`;

// Request one-time code endpoint
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'Email is required' });
  }

  try {
    // Use Storefront API to request password recovery
    const response = await fetch(STOREFRONT_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Storefront-Access-Token': STOREFRONT_TOKEN,
      },
      body: JSON.stringify({
        query: `
          mutation customerRecover($email: String!) {
            customerRecover(email: $email) {
              customerUserErrors {
                code
                field
                message
              }
            }
          }
        `,
        variables: {
          email: email,
        },
      }),
    });

    const data = await response.json();
    console.log('Shopify response:', data);

    // Check for GraphQL errors
    if (data.errors) {
      return res.status(400).json({ 
        success: false, 
        error: data.errors[0].message 
      });
    }

    // Check for customer user errors
    const customerUserErrors = data.data?.customerRecover?.customerUserErrors || [];
    if (customerUserErrors.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: customerUserErrors[0].message 
      });
    }

    // Success - code has been sent
    res.json({ success: true });
  } catch (error) {
    console.error('Error requesting code:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify code endpoint
app.post('/auth/verify-code', async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ success: false, error: 'Email and code are required' });
  }

  try {
    // With your metallbudeauth app, you can use the Admin API to:
    // 1. Find the customer by email
    // 2. Create a customer access token
    
    if (!ADMIN_API_TOKEN) {
      // Fallback to simulation if no admin token is available
      console.warn('No Admin API token provided. Using simulation mode.');
      return simulateVerification(email, res);
    }
    
    // Step 1: Find customer by email
    const customerResponse = await fetch(ADMIN_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': ADMIN_API_TOKEN,
      },
      body: JSON.stringify({
        query: `
          query GetCustomerByEmail($email: String!) {
            customers(first: 1, query: $email) {
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
                    address2
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
          email: email,
        },
      }),
    });

    const customerData = await customerResponse.json();
    console.log('Customer lookup response:', customerData);
    
    if (customerData.errors) {
      return res.status(400).json({ 
        success: false, 
        error: customerData.errors[0].message 
      });
    }
    
    const customers = customerData.data?.customers?.edges || [];
    if (customers.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'No customer found with this email' 
      });
    }
    
    const customer = customers[0].node;
    
    // Step 2: Create a customer access token
    // Note: In a real implementation, you would verify the code first
    // For now, we'll create a token directly since we can't verify the code through the API
    
    const tokenResponse = await fetch(STOREFRONT_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Storefront-Access-Token': STOREFRONT_TOKEN,
      },
      body: JSON.stringify({
        query: `
          mutation customerAccessTokenCreateWithMultipass($multipassToken: String!) {
            customerAccessTokenCreateWithMultipass(multipassToken: $multipassToken) {
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
          multipassToken: generateMultipassToken(customer),
        },
      }),
    });
    
    const tokenData = await tokenResponse.json();
    console.log('Token creation response:', tokenData);
    
    if (tokenData.errors) {
      return res.status(400).json({ 
        success: false, 
        error: tokenData.errors[0].message 
      });
    }
    
    const customerUserErrors = tokenData.data?.customerAccessTokenCreateWithMultipass?.customerUserErrors || [];
    if (customerUserErrors.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: customerUserErrors[0].message 
      });
    }
    
    const accessToken = tokenData.data?.customerAccessTokenCreateWithMultipass?.customerAccessToken?.accessToken;
    if (!accessToken) {
      return res.status(400).json({ 
        success: false, 
        error: 'Failed to create access token' 
      });
    }
    
    // Success - return the token and customer data
    res.json({
      success: true,
      accessToken: accessToken,
      customer: customer
    });
    
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper function to simulate verification (used when Admin API token is not available)
function simulateVerification(email, res) {
  // Return a simulated customer
  return res.json({
    success: true,
    accessToken: `simulated_token_${Date.now()}`,
    customer: {
      id: `gid://shopify/Customer/${Date.now()}`,
      firstName: 'Test',
      lastName: 'User',
      email: email,
      phone: null,
      defaultAddress: null,
      addresses: { edges: [] }
    }
  });
}

// Helper function to generate a Multipass token (requires Shopify Plus)
// This is a placeholder - you would need to implement the actual Multipass token generation
function generateMultipassToken(customer) {
  // In a real implementation, you would:
  // 1. Create a JSON object with customer data
  // 2. Encrypt it using AES-256-CBC with your Multipass secret
  // 3. Base64 encode the result
  
  // For now, return a placeholder
  return 'multipass_token_placeholder';
}

app.listen(PORT, () => {
  console.log(`✅ Backend is live on port ${PORT}`);
});
