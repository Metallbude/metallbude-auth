#!/usr/bin/env node

const axios = require('axios');

const BASE_URL = 'https://metallbude-auth.onrender.com';

async function debugWishlistData() {
    try {
        console.log('🔍 [DEBUG] Getting public wishlist data for customer 7778195628324...\n');
        
        const response = await axios.get(`${BASE_URL}/api/public/wishlist/items?customerId=7778195628324`);
        
        console.log('📊 Response status:', response.status);
        console.log('📊 Number of items:', response.data.items?.length || 0);
        
        if (response.data.items) {
            response.data.items.forEach((item, index) => {
                console.log(`\n📋 Item ${index + 1}:`);
                console.log('   Product ID:', item.productId);
                console.log('   Variant ID:', item.variantId);
                console.log('   Selected Options:', item.selectedOptions);
                console.log('   SKU:', item.sku);
                console.log('   Title:', item.title);
                console.log('   Image URL:', item.imageUrl);
                console.log('   Price:', item.price);
                console.log('   Added At:', item.addedAt);
                console.log('   Synced From Firebase:', item.syncedFromFirebase);
            });
        }
        
    } catch (error) {
        if (error.response) {
            console.error('❌ API Error:', error.response.status, error.response.data);
        } else {
            console.error('❌ Network Error:', error.message);
        }
    }
}

debugWishlistData().catch(console.error);
