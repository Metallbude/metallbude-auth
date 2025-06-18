#!/usr/bin/env node

const axios = require('axios');

async function testMobileEndpoint() {
    const baseURL = 'https://metallbude-auth.onrender.com';
    
    console.log('📱 Testing Mobile App Endpoint: /customer/wishlist\n');
    
    try {
        // Test the mobile endpoint (this will fail without auth, but we can see the error)
        console.log('1️⃣ Testing /customer/wishlist (mobile app endpoint)...');
        try {
            const mobileResponse = await axios.get(`${baseURL}/customer/wishlist`);
            console.log('✅ Mobile endpoint response:', mobileResponse.data);
        } catch (authError) {
            console.log('🔒 Expected auth error:', authError.response?.status, authError.response?.statusText);
            console.log('   This endpoint requires authentication (mobile app token)');
        }
        
        // Compare with public endpoint
        console.log('\n2️⃣ Comparing with public endpoint...');
        const publicResponse4088 = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=4088060379300`);
        const publicResponse8084 = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=8084698890436`);
        
        console.log('📊 Public endpoint results:');
        console.log(`   Customer 4088060379300: ${publicResponse4088.data.count} items`);
        console.log(`   Customer 8084698890436: ${publicResponse8084.data.count} items`);
        
        if (publicResponse4088.data.count > 0) {
            console.log('\n📋 Customer 4088060379300 items:');
            publicResponse4088.data.items.forEach((item, i) => {
                console.log(`   ${i+1}. Product ID: ${item.productId}`);
            });
        }
        
        console.log('\n3️⃣ ANALYSIS:');
        console.log('   Your mobile app uses: /customer/wishlist (authenticated)');
        console.log('   Your web uses: /api/public/wishlist/items (public)');
        console.log('   They may be reading from different data sources!');
        
        // Check server logs for any recent mobile app requests
        console.log('\n4️⃣ The mobile endpoint might be:');
        console.log('   - Reading from Firebase (different customer data)');
        console.log('   - Reading from Shopify metafields (cached/old data)');
        console.log('   - Using different customer authentication');
        
    } catch (error) {
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

testMobileEndpoint();
