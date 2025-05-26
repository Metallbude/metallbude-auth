// Add these imports
import crypto from 'crypto';
import nodemailer from 'nodemailer'; // You'll need to install this: npm install nodemailer

// Add a storage for verification codes (in a real app, use a database)
const verificationCodes = {};

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

    // Step 3: Generate a verification code
    const verificationCode = crypto.randomInt(100000, 999999).toString();
    
    // Store the code with the email (with expiration)
    verificationCodes[email] = {
      code: verificationCode,
      expires: Date.now() + 15 * 60 * 1000, // 15 minutes expiration
    };
    
    console.log(`Generated code for ${email}: ${verificationCode}`);
    
    // Step 4: Send a custom email with the code
    const transporter = nodemailer.createTransport({
      service: 'gmail', // or your preferred email service
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Dein Anmeldecode für Metallbude',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Willkommen bei Metallbude</h2>
          <p>Hier ist dein Anmeldecode:</p>
          <div style="background-color: #f4f4f4; padding: 15px; font-size: 24px; text-align: center; letter-spacing: 5px; font-weight: bold;">
            ${verificationCode}
          </div>
          <p>Dieser Code ist 15 Minuten gültig.</p>
          <p>Falls du diese E-Mail nicht angefordert hast, kannst du sie ignorieren.</p>
        </div>
      `,
    };
    
    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${email}`);

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
    // Check if we have a stored code for this email
    const storedData = verificationCodes[email];
    
    if (!storedData) {
      return res.status(400).json({ 
        success: false, 
        error: 'Kein Code für diese E-Mail-Adresse angefordert oder Code ist abgelaufen' 
      });
    }
    
    // Check if code is expired
    if (Date.now() > storedData.expires) {
      delete verificationCodes[email]; // Clean up expired code
      return res.status(400).json({ 
        success: false, 
        error: 'Code ist abgelaufen. Bitte fordere einen neuen Code an' 
      });
    }
    
    // Check if code matches
    if (storedData.code !== code) {
      return res.status(400).json({ 
        success: false, 
        error: 'Ungültiger Code' 
      });
    }
    
    // Code is valid, clean it up
    delete verificationCodes[email];
    
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
      
      if (!customerData.errors) {
        const customers = customerData.data?.customers?.edges || [];
        if (customers.length > 0) {
          customer = customers[0].node;
        }
      }
    }
    
    // Generate a simulated token (in a real app, use JWT or similar)
    const accessToken = `simulated_token_${Date.now()}`;
    
    // Return success with customer data
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
