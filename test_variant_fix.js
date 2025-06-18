#!/usr/bin/env node

const axios = require('axios');

const BASE_URL = 'https://metallbude-auth.onrender.com';

async function testVariantStorage() {
    console.log('🧪 Testing variant information storage...\n');
    
    // Test data
    const testCustomerId = 'gid://shopify/Customer/7778195628324';
    const testProductId = 'gid://shopify/Product/8877845946660';
    const testVariantId = 'gid://shopify/ProductVariant/47473951629604';
    const testSelectedOptions = {
        'Farbe': 'Pink Lemonade'
    };

    try {
        console.log('1. Testing mobile add to wishlist with variant info...');
        
        // Simulate what the Flutter app sends
        const addResponse = await axios.post(`${BASE_URL}/customer/wishlist`, {
            productId: testProductId,
            action: 'add',
            variantId: testVariantId,
            selectedOptions: testSelectedOptions
        }, {
            headers: {
                'Authorization': 'Bearer test-token',
                'Content-Type': 'application/json'
            }
        });
        
        console.log('✅ Add response:', addResponse.data);
        
        console.log('\n2. Testing mobile get wishlist...');
        
        // Get wishlist back
        const getResponse = await axios.get(`${BASE_URL}/customer/wishlist`, {
            headers: {
                'Authorization': 'Bearer test-token'
            }
        });
        
        console.log('✅ Get response items:', getResponse.data.items?.length || 0);
        
        // Check if variant info is preserved
        const items = getResponse.data.items || [];
        const testItem = items.find(item => item.productId === testProductId);
        
        if (testItem) {
            console.log('📋 Test item found:');
            console.log('   Product ID:', testItem.productId);
            console.log('   Variant ID:', testItem.variantId);
            console.log('   Selected Options:', testItem.selectedOptions);
            console.log('   SKU:', testItem.sku);
            
            if (testItem.selectedOptions?.Farbe === 'Pink Lemonade') {
                console.log('✅ SUCCESS: Variant information is preserved!');
            } else {
                console.log('❌ FAIL: Variant information lost!');
                console.log('   Expected: { Farbe: "Pink Lemonade" }');
                console.log('   Got:', testItem.selectedOptions);
            }
        } else {
            console.log('❌ Test item not found in wishlist');
        }
        
        console.log('\n3. Cleaning up test item...');
        
        // Clean up
        await axios.post(`${BASE_URL}/customer/wishlist`, {
            productId: testProductId,
            action: 'remove',
            variantId: testVariantId,
            selectedOptions: testSelectedOptions
        }, {
            headers: {
                'Authorization': 'Bearer test-token',
                'Content-Type': 'application/json'
            }
        });
        
        console.log('✅ Test cleanup completed');
        
    } catch (error) {
        if (error.response) {
            console.error('❌ API Error:', error.response.status, error.response.data);
        } else {
            console.error('❌ Network Error:', error.message);
        }
    }
}

// Run the test
testVariantStorage().catch(console.error);
