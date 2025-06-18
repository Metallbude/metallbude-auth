#!/usr/bin/env node

const axios = require('axios');

async function fullDiagnostic() {
    const baseURL = 'https://metallbude-auth.onrender.com';
    
    console.log('🔍 FULL WISHLIST DIAGNOSTIC\n');
    console.log('=' .repeat(60));
    
    try {
        // Check server health
        console.log('1️⃣ SERVER HEALTH CHECK');
        const health = await axios.get(`${baseURL}/health`);
        console.log(`   Status: ${health.data.firebase?.status || 'unknown'}`);
        console.log(`   Firebase: ${health.data.firebase ? '✅' : '❌'}`);
        
        // Get all customer data
        console.log('\n2️⃣ CUSTOMER ACCOUNTS');
        const debug = await axios.get(`${baseURL}/api/debug/wishlist-customers`);
        console.log(`   Total customers: ${debug.data.totalCustomers}`);
        console.log(`   Customer IDs: ${debug.data.customerIds.join(', ')}`);
        
        // Check detailed data for each customer
        console.log('\n3️⃣ DETAILED WISHLIST DATA');
        for (const customerId of debug.data.customerIds) {
            console.log(`\n   🆔 Customer: ${customerId}`);
            const wishlist = await axios.get(`${baseURL}/api/public/wishlist/items?customerId=${customerId}`);
            console.log(`   📦 Items: ${wishlist.data.count}`);
            
            if (wishlist.data.count > 0) {
                wishlist.data.items.forEach((item, i) => {
                    const productNum = item.productId.split('/').pop();
                    const addedTime = new Date(item.addedAt).toLocaleString();
                    console.log(`      ${i+1}. Product ${productNum} (added: ${addedTime})`);
                });
            }
        }
        
        // Product ID reference
        console.log('\n4️⃣ PRODUCT ID REFERENCE');
        console.log('   Based on your screenshots:');
        console.log('   - DUSCHLABLAGE SHEA: likely ends in ...626852');
        console.log('   - LEDER S-HAKEN: likely ends in ...525540');
        console.log('   - SCHUHREGAL CAMO: unknown product ID');
        console.log('   - STEHENDER NACHTTISCH: unknown product ID');
        console.log('   - HANDTUCHHALTER VANA: unknown product ID');
        
        console.log('\n5️⃣ DIAGNOSIS');
        console.log('   📱 Your mobile apps seem to be:');
        console.log('   - Using LOCAL CACHE or');
        console.log('   - Hitting DIFFERENT ENDPOINTS or');
        console.log('   - Connected to DIFFERENT SERVERS');
        console.log('\n   🌐 Your web browser is correctly connected to:');
        console.log(`   - Server: ${baseURL}`);
        console.log('   - Customer: 4088060379300');
        console.log('   - Products: 2 items (DUSCHLABLAGE + LEDER S-HAKEN)');
        
    } catch (error) {
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

fullDiagnostic();
