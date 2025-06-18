#!/usr/bin/env node

const axios = require('axios');

async function debugFullFirebaseStructure() {
    try {
        console.log('🔍 [DEBUG] Getting full Firebase structure...\n');
        
        const response = await axios.get('https://metallbude-auth.onrender.com/api/debug/wishlist-customers');
        
        console.log('📊 All Firebase customers:');
        console.log(JSON.stringify(response.data, null, 2));
        
        // Look for the customer that has 5 items (that's likely the mobile user)
        const customerIds = response.data.customerIds || [];
        const mobileCustomer = customerIds.find(id => response.data.dataSnapshot[id] === 5);
        
        if (mobileCustomer) {
            console.log(`\n🎯 Mobile customer (5 items): ${mobileCustomer}`);
            
            // Extract the numeric ID
            const numericId = mobileCustomer.replace(/[^0-9]/g, '');
            console.log(`📱 Numeric customer ID: ${numericId}`);
            
            // Now try to get the public wishlist for this customer
            console.log(`\n🌐 Testing public wishlist for customer ${numericId}...`);
            const publicResponse = await axios.get(`https://metallbude-auth.onrender.com/api/public/wishlist/items?customerId=${numericId}`);
            
            console.log('📊 Public API response:');
            console.log('   Status:', publicResponse.status);
            console.log('   Items count:', publicResponse.data.items?.length || 0);
            
            if (publicResponse.data.items?.length > 0) {
                console.log('\n📋 Sample item:');
                const item = publicResponse.data.items[0];
                console.log('   Product ID:', item.productId);
                console.log('   Variant ID:', item.variantId);
                console.log('   Selected Options:', item.selectedOptions);
                console.log('   Image URL:', item.imageUrl);
            }
        }
        
    } catch (error) {
        if (error.response) {
            console.error('❌ Error:', error.response.status, error.response.data);
        } else {
            console.error('❌ Error:', error.message);
        }
    }
}

debugFullFirebaseStructure().catch(console.error);
