// Wishlist API endpoints for metallbude_auth backend
// This module exports a function that adds wishlist routes to an Express app

const fs = require('fs').promises;
const path = require('path');

module.exports = function(app) {
    // Get authenticateToken middleware from the main app
    const authenticateToken = app.authenticateToken || ((req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) return res.sendStatus(401);

        // Simple token validation - replace with your actual auth logic
        if (token) {
            req.user = { customerId: 'default-customer' }; // Temporary fallback
            next();
        } else {
            res.sendStatus(403);
        }
    });

// Wishlist data storage (JSON file)
const WISHLIST_FILE = path.join(__dirname, 'data', 'wishlists.json');

// Ensure data directory exists
async function ensureDataDirectory() {
    const dataDir = path.dirname(WISHLIST_FILE);
    try {
        await fs.access(dataDir);
    } catch {
        await fs.mkdir(dataDir, { recursive: true });
    }
}

// Load wishlist data
async function loadWishlistData() {
    try {
        const data = await fs.readFile(WISHLIST_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // File doesn't exist or is empty, return empty object
        return {};
    }
}

// Save wishlist data
async function saveWishlistData(data) {
    await ensureDataDirectory();
    await fs.writeFile(WISHLIST_FILE, JSON.stringify(data, null, 2));
}

// Get customer ID from Shopify customer access token
function extractCustomerIdFromToken(token) {
    try {
        const decoded = Buffer.from(token, 'base64').toString('utf8');
        const tokenData = JSON.parse(decoded);
        
        if (tokenData.customerId) {
            // Extract numeric ID from Shopify GID format
            const customerId = tokenData.customerId.toString();
            if (customerId.startsWith('gid://shopify/Customer/')) {
                return customerId.split('/').pop();
            }
            return customerId;
        }
        return null;
    } catch (error) {
        console.error('Error extracting customer ID:', error);
        return null;
    }
}

// Shopify integration for syncing wishlist to customer metafields
async function syncToShopifyCustomerMetafields(customerId, wishlistItems) {
    try {
        const shopifyAccessToken = process.env.SHOPIFY_ACCESS_TOKEN;
        const shopifyDomain = process.env.SHOPIFY_DOMAIN || 'metallbude.myshopify.com';
        
        if (!shopifyAccessToken) {
            console.log('No Shopify access token - skipping sync');
            return;
        }

        // Extract just the customer ID number from the GID format
        const customerIdNumber = customerId.includes('Customer/') 
            ? customerId.split('Customer/')[1] 
            : customerId;

        // Prepare wishlist data for Shopify metafield
        const wishlistData = {
            metafield: {
                namespace: 'custom',
                key: 'wishlist_items',
                value: JSON.stringify(wishlistItems.map(item => ({
                    productId: item.productId,
                    variantId: item.variantId,
                    title: item.title,
                    selectedOptions: item.selectedOptions,
                    addedAt: item.createdAt
                }))),
                type: 'json'
            }
        };

        // Update customer metafield in Shopify
        const response = await fetch(`https://${shopifyDomain}/admin/api/2023-10/customers/${customerIdNumber}/metafields.json`, {
            method: 'POST',
            headers: {
                'X-Shopify-Access-Token': shopifyAccessToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(wishlistData)
        });

        if (response.ok) {
            console.log('✅ Wishlist synced to Shopify customer metafields');
        } else {
            console.log('⚠️ Failed to sync wishlist to Shopify:', response.status);
        }
    } catch (error) {
        console.error('Error syncing to Shopify metafields:', error);
    }
}

// WISHLIST API ENDPOINTS

// Get wishlist items for a customer
app.get('/api/wishlist/items', authenticateToken, async (req, res) => {
    try {
        const customerId = req.user.customerId || extractCustomerIdFromToken(req.headers.authorization?.replace('Bearer ', ''));
        
        if (!customerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        const wishlistData = await loadWishlistData();
        const customerWishlist = wishlistData[customerId] || [];

        res.json({
            success: true,
            items: customerWishlist,
            count: customerWishlist.length
        });
    } catch (error) {
        console.error('Error getting wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add item to wishlist
app.post('/api/wishlist/add', authenticateToken, async (req, res) => {
    try {
        const customerId = req.user.customerId || extractCustomerIdFromToken(req.headers.authorization?.replace('Bearer ', ''));
        
        if (!customerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        const {
            productId,
            variantId,
            title,
            imageUrl,
            price,
            compareAtPrice,
            sku,
            selectedOptions
        } = req.body;

        if (!productId || !title) {
            return res.status(400).json({ error: 'Product ID and title are required' });
        }

        const wishlistData = await loadWishlistData();
        
        if (!wishlistData[customerId]) {
            wishlistData[customerId] = [];
        }

        // Check if item already exists
        const existingItemIndex = wishlistData[customerId].findIndex(item => 
            item.productId === productId && 
            item.variantId === variantId &&
            JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
        );

        if (existingItemIndex !== -1) {
            return res.json({
                success: true,
                message: 'Item already in wishlist',
                alreadyExists: true
            });
        }

        // Add new item
        const newItem = {
            id: Date.now().toString(),
            productId,
            variantId: variantId || productId,
            title,
            imageUrl,
            price: parseFloat(price) || 0,
            compareAtPrice: compareAtPrice ? parseFloat(compareAtPrice) : null,
            sku,
            selectedOptions: selectedOptions || {},
            createdAt: new Date().toISOString()
        };

        wishlistData[customerId].push(newItem);
        await saveWishlistData(wishlistData);
        await syncToShopifyCustomerMetafields(customerId, wishlistData[customerId]); // Sync to Shopify

        res.json({
            success: true,
            message: 'Item added to wishlist',
            item: newItem
        });
    } catch (error) {
        console.error('Error adding to wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Remove item from wishlist
app.delete('/api/wishlist/remove', authenticateToken, async (req, res) => {
    try {
        const customerId = req.user.customerId || extractCustomerIdFromToken(req.headers.authorization?.replace('Bearer ', ''));
        
        if (!customerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        const { productId, variantId, selectedOptions } = req.body;

        if (!productId) {
            return res.status(400).json({ error: 'Product ID is required' });
        }

        const wishlistData = await loadWishlistData();
        
        if (!wishlistData[customerId]) {
            return res.json({ success: true, message: 'Item not in wishlist' });
        }

        // Find and remove item
        const itemIndex = wishlistData[customerId].findIndex(item => 
            item.productId === productId && 
            item.variantId === (variantId || productId) &&
            JSON.stringify(item.selectedOptions || {}) === JSON.stringify(selectedOptions || {})
        );

        if (itemIndex === -1) {
            return res.json({ success: true, message: 'Item not found in wishlist' });
        }

        wishlistData[customerId].splice(itemIndex, 1);
        await saveWishlistData(wishlistData);
        await syncToShopifyCustomerMetafields(customerId, wishlistData[customerId]); // Sync to Shopify

        res.json({
            success: true,
            message: 'Item removed from wishlist'
        });
    } catch (error) {
        console.error('Error removing from wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Clear entire wishlist
app.delete('/api/wishlist/clear', authenticateToken, async (req, res) => {
    try {
        const customerId = req.user.customerId || extractCustomerIdFromToken(req.headers.authorization?.replace('Bearer ', ''));
        
        if (!customerId) {
            return res.status(400).json({ error: 'Customer ID not found' });
        }

        const wishlistData = await loadWishlistData();
        wishlistData[customerId] = [];
        await saveWishlistData(wishlistData);
        await syncToShopifyCustomerMetafields(customerId, wishlistData[customerId]); // Sync to Shopify

        res.json({
            success: true,
            message: 'Wishlist cleared'
        });
    } catch (error) {
        console.error('Error clearing wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

}; // End of module.exports function