#!/usr/bin/env node

const axios = require('axios');

async function diagnoseCustomerAccounts() {
    const baseURL = 'https://metallbude-auth.onrender.com';
    
    console.log('🔍 Customer Account Diagnostic\n');
    
    try {
        // Get customer data
        const debugResponse = await axios.get(`${baseURL}/api/debug/wishlist-customers`);
        const customerIds = debugResponse.data.customerIds;
        
        console.log('📋 Found customer accounts:');
        console.log('=' .repeat(50));
        
        for (const customerId of customerIds) {
            console.log(`\n🆔 Customer ID: ${customerId}`);
            
            // Get wishlist data
            const wishlistResponse = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=${customerId}`);
            const itemCount = wishlistResponse.data.count;
            
            console.log(`📦 Wishlist items: ${itemCount}`);
            
            if (itemCount > 0) {
                console.log('📄 Items:');
                wishlistResponse.data.items.forEach((item, index) => {
                    console.log(`   ${index + 1}. Product ${item.productId.split('/').pop()}`);
                    console.log(`      Added: ${new Date(item.addedAt).toLocaleString()}`);
                });
            }
            
            console.log('-' .repeat(30));
        }
        
        console.log('\n🎯 DIAGNOSIS:');
        console.log('If your mobile app shows 0 items but web shows 2 items:');
        console.log('- Your mobile app is likely using customer ID: 8084698890436 (0 items)');
        console.log('- Your web session is likely using customer ID: 4088060379300 (2 items)');
        console.log('- You may need to log out and log back in on mobile to sync accounts');
        
    } catch (error) {
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

diagnoseCustomerAccounts();
