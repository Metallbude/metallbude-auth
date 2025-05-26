const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');

const app = express();
const PORT = 3000;

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
      },
      body: JSON.stringify({
        email,
        code,
        shop: 'metallbude.com',
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

app.listen(PORT, () => {
  console.log(`✅ Backend is running at http://localhost:${PORT}`);
});