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
      try {
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
        console.log('Customer lookup response:', JSON.stringify(customerData, null, 2));
        
        if (!customerData.errors) {
          const customers = customerData.data?.customers?.edges || [];
          if (customers.length > 0) {
            customerExists = true;
            customerId = customers[0].node.id;
            console.log(`Customer exists with ID: ${customerId}`);
          } else {
            console.log(`No customer found with email: ${email}`);
          }
        } else {
          console.error('Error looking up customer:', customerData.errors);
        }
      } catch (error) {
        console.error('Exception during customer lookup:', error);
        // Continue with the flow even if customer lookup fails
      }
    } else {
      console.warn('No ADMIN_API_TOKEN provided, skipping customer lookup');
    }
    
    // Step 2: If customer doesn't exist, create one
    if (!customerExists && ADMIN_API_TOKEN) {
      console.log(`Creating new customer with email: ${email}`);
      
      try {
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
        console.log('Customer creation response:', JSON.stringify(createData, null, 2));
        
        if (createData.errors) {
          console.error('GraphQL errors during customer creation:', createData.errors);
          // Don't return error, try to continue with the flow
        } else {
          const userErrors = createData.data?.customerCreate?.userErrors || [];
          if (userErrors.length > 0) {
            console.error('User errors during customer creation:', userErrors);
            // Check if the error is because the customer already exists
            const alreadyExistsError = userErrors.some(err => 
              err.message?.includes('already exists') || 
              err.message?.includes('bereits existiert')
            );
            
            if (alreadyExistsError) {
              console.log('Customer already exists, continuing with the flow');
              customerExists = true;
            }
            // Don't return error, try to continue with the flow
          } else {
            customerId = createData.data?.customerCreate?.customer?.id;
            if (customerId) {
              customerExists = true;
              console.log(`New customer created with ID: ${customerId}`);
            }
          }
        }
      } catch (error) {
        console.error('Exception during customer creation:', error);
        // Continue with the flow even if customer creation fails
      }
    }

    // Step 3: Send the recovery email
    try {
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
      console.log('Shopify recovery response:', JSON.stringify(data, null, 2));

      // Check for GraphQL errors
      if (data.errors) {
        console.error('GraphQL errors during recovery:', data.errors);
        return res.status(400).json({ 
          success: false, 
          error: data.errors[0].message 
        });
      }

      // Check for customer user errors
      const customerUserErrors = data.data?.customerRecover?.customerUserErrors || [];
      if (customerUserErrors.length > 0) {
        console.error('Customer user errors during recovery:', customerUserErrors);
        return res.status(400).json({ 
          success: false, 
          error: customerUserErrors[0].message 
        });
      }

      // Success - code has been sent
      console.log('Recovery email sent successfully');
      res.json({ 
        success: true,
        isNewCustomer: !customerExists
      });
    } catch (error) {
      console.error('Exception during recovery:', error);
      return res.status(500).json({ 
        success: false, 
        error: `Fehler beim Senden des Codes: ${error.message}` 
      });
    }
  } catch (error) {
    console.error('General error in request-code endpoint:', error);
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
    // With the new customer accounts system, we need to:
    // 1. Redirect the user to a special URL that includes the code
    // 2. Capture the token from the redirect
    
    // Since we can't do this directly in a mobile app without WebView,
    // we'll use a workaround that simulates the verification:
    
    // For demonstration purposes, we'll create a session token
    // In a real implementation, you would need a backend service to:
    // - Verify the code against Shopify's system
    // - Generate a valid customer access token
    
    // Get customer data from Shopify
    let customer = {
      id: `gid://shopify/Customer/${Date.now()}`,
      firstName: '',
      lastName: '',
      email: email,
      phone: null,
      defaultAddress: null,
      addresses: { edges: [] }
    };
    
    if (ADMIN_API_TOKEN) {
      try {
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
              query: email,
            },
          }),
        });

        const customerData = await customerResponse.json();
        console.log('Customer lookup response:', JSON.stringify(customerData, null, 2));
        
        if (!customerData.errors) {
          const customers = customerData.data?.customers?.edges || [];
          if (customers.length > 0) {
            customer = customers[0].node;
            console.log(`Found customer: ${customer.id}`);
          } else {
            console.log(`No customer found with email: ${email}`);
          }
        } else {
          console.error('Error looking up customer:', customerData.errors);
        }
      } catch (error) {
        console.error('Exception during customer lookup:', error);
      }
    }
    
    // Simulate successful verification
    const simulatedToken = `simulated_token_${Date.now()}`;
    
    // Return success with customer data
    res.json({
      success: true,
      accessToken: simulatedToken,
      customer: customer
    });
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend is live on port ${PORT}`);
});
