#!/usr/bin/env node

// Test script to verify that the wishlist API is returning correct variant info
const https = require('https');

const API_BASE = 'https://metallbude-auth.onrender.com';

// Test data - simulate a real session token (you'll need to replace this)
const testCustomerId = 'gid://shopify/Customer/7719334158593'; // Your test customer ID

async function makeRequest(path, method = 'GET', data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(API_BASE + path);
    
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Test Script',
        ...headers
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed, headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, data: body, headers: res.headers });
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

async function testWishlistAPI() {
  console.log('🧪 Testing Wishlist API Variant Info...\n');

  try {
    // Test 1: Get public wishlist items
    console.log('📋 Test 1: Getting public wishlist items...');
    const publicResponse = await makeRequest(`/api/public/wishlist/items?customerId=web_${testCustomerId}`);
    
    if (publicResponse.status === 200 && publicResponse.data.success) {
      console.log(`✅ Found ${publicResponse.data.items.length} wishlist items`);
      
      publicResponse.data.items.forEach((item, index) => {
        console.log(`\n📦 Item ${index + 1}: ${item.title}`);
        console.log(`   🆔 Product ID: ${item.productId}`);
        console.log(`   🏷️ Variant ID: ${item.variantId}`);
        console.log(`   📋 SKU: ${item.sku}`);
        console.log(`   🎨 Selected Options: ${JSON.stringify(item.selectedOptions)}`);
        console.log(`   🖼️ Image URL: ${item.imageUrl ? item.imageUrl.substring(0, 50) + '...' : 'none'}`);
        console.log(`   💰 Price: €${item.price}`);
        
        // Check if this looks like correct variant info
        const hasVariantInfo = item.selectedOptions && Object.keys(item.selectedOptions).length > 0;
        const hasImage = item.imageUrl && item.imageUrl.includes('variant');
        
        if (hasVariantInfo) {
          console.log(`   ✅ Has variant info: ${JSON.stringify(item.selectedOptions)}`);
        } else {
          console.log(`   ❌ Missing variant info`);
        }
        
        if (hasImage) {
          console.log(`   ✅ Has variant-specific image`);
        } else {
          console.log(`   ⚠️ May be using default product image`);
        }
      });
    } else {
      console.log(`❌ Public API failed: ${publicResponse.status}`, publicResponse.data);
    }

  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run the test
testWishlistAPI().then(() => {
  console.log('\n🏁 Test completed');
}).catch(console.error);
