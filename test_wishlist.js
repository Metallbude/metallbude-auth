const axios = require('axios');

async function testWishlistEndpoints() {
    console.log('🧪 Testing wishlist endpoints...\n');
    
    // Test 1: Public endpoint (should show 2 items after sync)
    try {
        console.log('1️⃣ Testing public endpoint...');
        const publicResponse = await axios.get('https://metallbude-auth.onrender.com/api/public/wishlist/items?customerId=4088060379300');
        console.log(`✅ Public endpoint: ${publicResponse.data.count} items`);
        console.log('   Items:', publicResponse.data.items.map(item => item.productId));
    } catch (error) {
        console.error('❌ Public endpoint error:', error.response?.data || error.message);
    }
    
    console.log('\n');
    
    // Test 2: Try to get a session token first (this simulates mobile app login)
    try {
        console.log('2️⃣ Testing authenticated endpoint (simulating mobile app)...');
        console.log('   Note: This will fail without a valid session token, but we can check server logs');
        
        const authResponse = await axios.get('https://metallbude-auth.onrender.com/customer/wishlist', {
            headers: {
                'Authorization': 'Bearer invalid-token-for-testing'
            }
        });
        console.log('✅ Authenticated endpoint response:', authResponse.data);
    } catch (error) {
        console.log('ℹ️  Expected auth error (no valid token):', error.response?.status, error.response?.statusText);
        console.log('   This is expected - we need to check server logs for the real mobile app requests');
    }
    
    console.log('\n');
    
    // Test 3: Health check
    try {
        console.log('3️⃣ Testing sync health check...');
        const healthResponse = await axios.get('https://metallbude-auth.onrender.com/api/health/sync');
        console.log('✅ Health check:', healthResponse.data);
    } catch (error) {
        console.error('❌ Health check error:', error.response?.data || error.message);
    }
}

testWishlistEndpoints();
