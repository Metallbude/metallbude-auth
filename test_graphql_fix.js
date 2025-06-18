const axios = require('axios');

const BASE_URL = 'https://metallbude-auth.onrender.com';

async function testMobileWishlistEndpoint() {
  console.log('🧪 Testing mobile wishlist endpoint after GraphQL fixes...\n');
  
  try {
    // Test mobile wishlist endpoint with valid customer token
    const response = await axios.get(`${BASE_URL}/customer/wishlist`, {
      headers: {
        'Authorization': 'Bearer your-valid-token-here',
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ Mobile wishlist endpoint response:');
    console.log('   Status:', response.status);
    console.log('   Data:', JSON.stringify(response.data, null, 2));
    
    if (response.data.wishlist && response.data.wishlist.length > 0) {
      console.log('\n🎉 SUCCESS: Wishlist products are now being returned!');
      console.log(`   Found ${response.data.wishlist.length} products in wishlist`);
    } else {
      console.log('\n📭 INFO: Wishlist is empty (this is normal if no items are added)');
    }
    
  } catch (error) {
    if (error.response) {
      console.log('❌ HTTP Error:', error.response.status);
      console.log('   Response:', error.response.data);
    } else {
      console.log('❌ Network Error:', error.message);
    }
  }
}

async function testPublicWishlistEndpoint() {
  console.log('\n🧪 Testing public wishlist endpoint...\n');
  
  try {
    const response = await axios.get(`${BASE_URL}/api/public/wishlist/items?customerId=4088060379300`);
    
    console.log('✅ Public wishlist endpoint response:');
    console.log('   Status:', response.status);
    console.log('   Data:', JSON.stringify(response.data, null, 2));
    
  } catch (error) {
    if (error.response) {
      console.log('❌ HTTP Error:', error.response.status);
      console.log('   Response:', error.response.data);
    } else {
      console.log('❌ Network Error:', error.message);
    }
  }
}

// Run tests
async function runTests() {
  await testPublicWishlistEndpoint();
  console.log('\n' + '='.repeat(60) + '\n');
  await testMobileWishlistEndpoint();
}

runTests();
