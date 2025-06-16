// Wishlist API endpoints for metallbude_auth backend
// Add these to your existing index.js file

const fs = require('fs').promises;
const path = require('path');

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

        res.json({
            success: true,
            message: 'Wishlist cleared'
        });
    } catch (error) {
        console.error('Error clearing wishlist:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
