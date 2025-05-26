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

// Shopify GraphQL API endpoint
const SHOPIFY_GRAPHQL_URL = `https://${process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude-de.myshopify.com'}/api/2023-04/graphql.json`;
const SHOPIFY_STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN || '5ec4924dbec617fffa5eab30334493d1';

// Request one-time code endpoint
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'Email is required' });
  }

  try {
    const response = await fetch(SHOPIFY_GRAPHQL_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Storefront-Access-Token': SHOPIFY_STOREFRONT_TOKEN,
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

// Verify code endpoint (simulation)
app.post('/auth/verify-code', async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ success: false, error: 'Email and code are required' });
  }

  try {
    // NOTE: This is a simulation since Shopify doesn't provide a direct API to verify codes
    // In a real implementation, you would need to use Shopify Admin API or a custom solution
    
    // For testing purposes, we'll accept any code and return a simulated customer
    // In production, you would need to implement proper verification
    
    // Simulate a delay to make it feel like verification is happening
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Return a simulated customer
    res.json({
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
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend is live on port ${PORT}`);
});
