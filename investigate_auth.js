#!/usr/bin/env node

const axios = require('axios');

async function investigateCustomerAuth() {
    const baseURL = 'https://metallbude-auth.onrender.com';
    
    console.log('🔍 INVESTIGATING CUSTOMER AUTHENTICATION MISMATCH\n');
    
    try {
        // 1. Get all customer data
        console.log('1️⃣ Current server state:');
        const debugResponse = await axios.get(`${baseURL}/api/debug/wishlist-customers`);
        console.log('   Server customers:', debugResponse.data.customerIds);
        console.log('   Data counts:', debugResponse.data.dataSnapshot);
        
        // 2. Check if we can find which endpoints your mobile app is actually hitting
        console.log('\n2️⃣ Testing both customer endpoints:');
        
        // Test public endpoint
        for (const customerId of debugResponse.data.customerIds) {
            const publicResponse = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=${customerId}`);
            console.log(`   Public endpoint (customer ${customerId}): ${publicResponse.data.count} items`);
            
            if (publicResponse.data.count > 0) {
                console.log('      Product IDs:', publicResponse.data.items.map(item => item.productId.split('/').pop()));
            }
        }
        
        console.log('\n3️⃣ THE PROBLEM:');
        console.log('   Your mobile app uses: /customer/wishlist (requires authentication)');
        console.log('   Your web uses: /api/public/wishlist/items (no auth needed)');
        console.log('   They may be reading from different customer records!');
        
        console.log('\n4️⃣ DIAGNOSIS:');
        console.log('   When your mobile app authenticates, it gets a customer ID from Shopify');
        console.log('   This customer ID might be different from the web customer ID');
        console.log('   That explains why you see different products on different devices');
        
        console.log('\n5️⃣ SOLUTION:');
        console.log('   - Check what customer ID your mobile app authentication returns');
        console.log('   - Verify it matches the customer ID with the wishlist data');
        console.log('   - Your mobile apps might be using a different Shopify customer account');
        
    } catch (error) {
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

investigateCustomerAuth();
