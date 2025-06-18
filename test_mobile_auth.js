#!/usr/bin/env node

const axios = require('axios');

// This script tests the mobile authentication flow
async function testMobileAuth() {
    const baseURL = 'https://metallbude-auth.onrender.com';
    
    console.log('🧪 Testing mobile authentication flow...\n');
    
    try {
        // Test 1: Check health endpoint
        console.log('1️⃣ Testing health endpoint...');
        const healthResponse = await axios.get(`${baseURL}/health`);
        console.log('✅ Health check:', healthResponse.data.firebase?.status);
        
        // Test 2: Try the debug endpoint to see what customers exist
        console.log('\n2️⃣ Checking available customers...');
        const debugResponse = await axios.get(`${baseURL}/api/debug/wishlist-customers`);
        console.log('📋 Available customers:', debugResponse.data);
        
        // Test 3: Test the public endpoint with your customer ID
        console.log('\n3️⃣ Testing public wishlist endpoint...');
        const publicResponse = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=8084698890436`);
        console.log('📦 Public wishlist result:', publicResponse.data);
        
        // Test 4: If we have other customer IDs from debug, try them
        if (debugResponse.data.customers && debugResponse.data.customers.length > 0) {
            console.log('\n4️⃣ Testing with other available customer IDs...');
            for (const customerId of debugResponse.data.customers.slice(0, 3)) { // Test first 3
                const testResponse = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=${customerId}`);
                console.log(`   Customer ${customerId}: ${testResponse.data.count} items`);
            }
        }
        
    } catch (error) {
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

testMobileAuth();
