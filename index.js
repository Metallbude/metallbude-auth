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
    return res.status(400).json({ success: false, error: 'Email ist erforderlich' });
  }

  try {
    // Step 1: Check if the customer exists
    let customerExists = false;
    let customerId = null;
    
    if (ADMIN_API_TOKEN) {
      const customerResponse = await fetch(ADMIN_API_URL, {
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
            query: email,
          },
        }),
      });

      const customerData = await customerResponse.json();
      console.log('Customer lookup response:', customerData);
      
      if (!customerData.errors) {
        const customers = customerData.data?.customers?.edges || [];
        if (customers.length > 0) {
          customerExists = true;
          customerId = customers[0].node.id;
          console.log(`Customer exists with ID: ${customerId}`);
        }
      }
    }
    
    // Step 2: If customer doesn't exist, create one
    if (!customerExists && ADMIN_API_TOKEN) {
      console.log(`Creating new customer with email: ${email}`);
      
      const createCustomerResponse = await fetch(ADMIN_API_URL, {
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
                  email
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

      const createData = await createCustomerResponse.json();
      console.log('Customer creation response:', createData);
      
      if (createData.errors) {
        return res.status(400).json({ 
          success: false, 
          error: createData.errors[0].message 
        });
      }
      
      const userErrors = createData.data?.customerCreate?.userErrors || [];
      if (userErrors.length > 0) {
        return res.status(400).json({ 
          success: false, 
          error: userErrors[0].message 
        });
      }
      
      customerId = createData.data?.customerCreate?.customer?.id;
      if (customerId) {
        customerExists = true;
        console.log(`New customer created with ID: ${customerId}`);
      }
    }

    // Step 3: Send the recovery email
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
    console.log('Shopify recovery response:', data);

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
    res.json({ 
      success: true,
      isNewCustomer: !customerExists
    });
  } catch (error) {
    console.error('Error requesting code:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify code endpoint
app.post('/auth/verify-code', async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ success: false, error: 'Email und Code sind erforderlich' });
  }

  try {
    // For now, we'll simulate a successful verification
    // In a production environment, you would need to implement a proper verification system
    
    // Simulate a delay to make it feel like verification is happening
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Return a simulated customer with token
    res.json({
      success: true,
      accessToken: `simulated_token_${Date.now()}`,
      customer: {
        id: `gid://shopify/Customer/${Date.now()}`,
        firstName: '',
        lastName: '',
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
