#!/usr/bin/env node

// This script helps debug what's happening with variant information
// by checking the Firebase data directly and the mobile API response

const axios = require('axios');

async function debugFirebaseAndMobile() {
    try {
        console.log('🔍 [DEBUG] Checking Firebase wishlist data...\n');
        
        // This should show what's stored in Firebase
        const firebaseResponse = await axios.get('https://metallbude-auth.onrender.com/api/debug/wishlist-customers');
        
        console.log('📊 Firebase wishlist customers:');
        console.log('   Customer IDs:', firebaseResponse.data.customerIds);
        console.log('   Data snapshot:', firebaseResponse.data.dataSnapshot);
        
        // Check specific customer's data if it exists
        const customerIds = firebaseResponse.data.customerIds || [];
        const targetCustomer = customerIds.find(id => id.includes('7778195628324'));
        
        if (targetCustomer) {
            console.log(`\n🎯 Found customer: ${targetCustomer}`);
            console.log('   Items count:', firebaseResponse.data.dataSnapshot[targetCustomer]);
        } else {
            console.log('\n❌ Customer 7778195628324 not found in Firebase data');
            console.log('   Available customers:', customerIds);
        }
        
    } catch (error) {
        if (error.response) {
            console.error('❌ API Error:', error.response.status, error.response.data);
        } else {
            console.error('❌ Network Error:', error.message);
        }
    }
}

debugFirebaseAndMobile().catch(console.error);
