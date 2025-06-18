#!/usr/bin/env node

const { getFirestore } = require('./services/firebase');

async function checkFirebaseVariantData() {
    console.log('🔍 Checking Firebase wishlist data structure...\n');
    
    try {
        const db = getFirestore();
        const wishlistsRef = db.collection('wishlists');
        const snapshot = await wishlistsRef.get();
        
        if (snapshot.empty) {
            console.log('📭 No wishlist documents found in Firebase');
            return;
        }
        
        console.log(`📊 Found ${snapshot.size} wishlist documents\n`);
        
        snapshot.forEach(doc => {
            const data = doc.data();
            console.log(`👤 Customer: ${doc.id}`);
            console.log(`📧 Email: ${data.customerEmail}`);
            console.log(`📅 Updated: ${data.updatedAt}`);
            console.log(`📦 Items: ${data.items?.length || 0}`);
            
            if (data.items && data.items.length > 0) {
                console.log('🔍 Item structure analysis:');
                data.items.forEach((item, index) => {
                    console.log(`  Item ${index + 1}:`);
                    console.log(`    productId: ${item.productId}`);
                    console.log(`    variantId: ${item.variantId || '❌ MISSING'}`);
                    console.log(`    selectedOptions: ${item.selectedOptions ? JSON.stringify(item.selectedOptions) : '❌ MISSING'}`);
                    console.log(`    sku: ${item.sku || '❌ MISSING'}`);
                    console.log(`    addedAt: ${item.addedAt}`);
                    console.log('');
                });
            }
            console.log('─'.repeat(60));
        });
        
    } catch (error) {
        console.error('❌ Error checking Firebase data:', error);
    }
}

// Run the check
checkFirebaseVariantData().catch(console.error);
