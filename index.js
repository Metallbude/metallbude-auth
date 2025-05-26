require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// Shopify login code verification endpoint
app.post('/auth/verify-code', async (req, res) => {
  const { email, code } = req.body;

  try {
    const response = await fetch('https://customer-account.shopify.com/account/session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Storefront-Access-Token': process.env.SHOPIFY_STOREFRONT_TOKEN,
      },
      body: JSON.stringify({
        email,
        code,
        shop: process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude.com',
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(401).json({ success: false, error: data });
    }

    res.json({ success: true, customer: data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Shopify request one-time code endpoint
app.post('/auth/request-code', async (req, res) => {
  const { email } = req.body;

  try {
    const response = await fetch('https://customer-account.shopify.com/account/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Storefront-Access-Token': process.env.SHOPIFY_STOREFRONT_TOKEN,
      },
      body: JSON.stringify({
        email,
        shop: process.env.SHOPIFY_SHOP_DOMAIN || 'metallbude.com',
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(400).json({ success: false, error: data });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend is running at http://localhost:${PORT}`);
});