#!/usr/bin/env node

const { getFirestore } = require('./services/firebase');
const axios = require('axios');
const config = require('./services/firebase').config;

async function migrateFirebaseVariantData() {
    console.log('🔄 Migrating existing Firebase wishlist items to include variant information...\n');
    
    try {
        const db = getFirestore();
        const wishlistsRef = db.collection('wishlists');
        const snapshot = await wishlistsRef.get();
        
        if (snapshot.empty) {
            console.log('📭 No wishlist documents found');
            return;
        }
        
        for (const doc of snapshot.docs) {
            const data = doc.data();
            console.log(`\n👤 Processing customer: ${data.customerEmail}`);
            
            if (!data.items || data.items.length === 0) {
                console.log('  📭 No items to migrate');
                continue;
            }
            
            let hasUpdates = false;
            const updatedItems = [];
            
            for (const item of data.items) {
                console.log(`\n  🔍 Processing item: ${item.productId}`);
                
                // Skip if item already has variant info
                if (item.variantId && item.selectedOptions) {
                    console.log('    ✅ Already has variant info, skipping');
                    updatedItems.push(item);
                    continue;
                }
                
                try {
                    // Fetch product details from Shopify
                    const productQuery = `
                        query getProduct($productId: ID!) {
                            product(id: $productId) {
                                id
                                title
                                variants(first: 50) {
                                    edges {
                                        node {
                                            id
                                            title
                                            sku
                                            selectedOptions {
                                                name
                                                value
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    `;
                    
                    const response = await axios.post(
                        'https://metallbude.myshopify.com/admin/api/2023-10/graphql.json',
                        {
                            query: productQuery,
                            variables: { productId: item.productId }
                        },
                        {
                            headers: {
                                'X-Shopify-Access-Token': process.env.SHOPIFY_ADMIN_TOKEN,
                                'Content-Type': 'application/json'
                            }
                        }
                    );
                    
                    const product = response.data.data?.product;
                    if (!product) {
                        console.log('    ❌ Product not found, keeping as-is');
                        updatedItems.push(item);
                        continue;
                    }
                    
                    const variants = product.variants.edges.map(edge => edge.node);
                    console.log(`    📦 Found ${variants.length} variants`);
                    
                    // For items without variant info, use the first available variant
                    // This is better than no variant info at all
                    const defaultVariant = variants[0];
                    
                    if (defaultVariant) {
                        const selectedOptions = {};
                        defaultVariant.selectedOptions.forEach(opt => {
                            selectedOptions[opt.name] = opt.value;
                        });
                        
                        const updatedItem = {
                            ...item,
                            variantId: defaultVariant.id,
                            selectedOptions: selectedOptions,
                            sku: defaultVariant.sku
                        };
                        
                        console.log(`    ✅ Updated with variant: ${defaultVariant.title}`);
                        console.log(`    📋 SKU: ${defaultVariant.sku}`);
                        console.log(`    🎨 Options:`, selectedOptions);
                        
                        updatedItems.push(updatedItem);
                        hasUpdates = true;
                    } else {
                        console.log('    ⚠️ No variants found, keeping as-is');
                        updatedItems.push(item);
                    }
                    
                    // Add small delay to avoid rate limiting
                    await new Promise(resolve => setTimeout(resolve, 100));
                    
                } catch (error) {
                    console.error(`    ❌ Error processing item: ${error.message}`);
                    updatedItems.push(item); // Keep original item if error
                }
            }
            
            // Update Firebase document if we made changes
            if (hasUpdates) {
                console.log(`\n  💾 Updating Firebase document...`);
                await doc.ref.update({
                    items: updatedItems,
                    updatedAt: new Date().toISOString(),
                    migratedAt: new Date().toISOString()
                });
                console.log(`  ✅ Firebase document updated`);
            } else {
                console.log(`  📋 No updates needed`);
            }
        }
        
        console.log('\n🎉 Migration completed!');
        
    } catch (error) {
        console.error('❌ Migration error:', error);
    }
}

// Run the migration
migrateFirebaseVariantData().catch(console.error);
