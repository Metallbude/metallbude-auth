const { getFirestore, COLLECTIONS } = require('./firebase');

class WishlistService {
  constructor() {
    this.db = getFirestore();
  }

  // Get customer's wishlist
  async getWishlist(customerId, customerEmail) {
    try {
      console.log(`❤️ Fetching Firebase wishlist for customer: ${customerEmail} (${customerId})`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(customerId);
      const wishlistDoc = await wishlistRef.get();

      if (!wishlistDoc.exists) {
        console.log(`📝 No wishlist found for customer ${customerId}, returning empty list`);
        return [];
      }

      const wishlistData = wishlistDoc.data();
      const items = wishlistData.items || [];

      console.log(`✅ Found ${items.length} items in Firebase wishlist`);
      return items.map(item => ({
        productId: item.productId,
        addedAt: item.addedAt,
        customerEmail: customerEmail,
        customerId: customerId
      }));

    } catch (error) {
      console.error('❌ Firebase wishlist fetch error:', error);
      throw error;
    }
  }

  // Add product to wishlist
  async addToWishlist(customerId, customerEmail, productId) {
    try {
      console.log(`❤️ Adding product ${productId} to Firebase wishlist for ${customerEmail}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(customerId);
      const wishlistDoc = await wishlistRef.get();

      let items = [];
      if (wishlistDoc.exists) {
        const data = wishlistDoc.data();
        items = data.items || [];
      }

      // Check if item already exists
      const existingItemIndex = items.findIndex(item => item.productId === productId);
      if (existingItemIndex !== -1) {
        console.log(`⚠️ Product ${productId} already in wishlist`);
        return { success: true, action: 'add', productId, wishlistCount: items.length, alreadyExists: true };
      }

      // Add new item
      const newItem = {
        productId,
        addedAt: new Date().toISOString(),
        customerEmail,
        customerId
      };

      items.push(newItem);

      // Update Firestore
      await wishlistRef.set({
        customerId,
        customerEmail,
        items,
        updatedAt: new Date().toISOString(),
        createdAt: wishlistDoc.exists ? (wishlistDoc.data().createdAt || new Date().toISOString()) : new Date().toISOString()
      });

      console.log(`✅ Added product ${productId} to Firebase wishlist. Total items: ${items.length}`);
      return { success: true, action: 'add', productId, wishlistCount: items.length };

    } catch (error) {
      console.error('❌ Firebase add to wishlist error:', error);
      throw error;
    }
  }

  // Remove product from wishlist
  async removeFromWishlist(customerId, customerEmail, productId) {
    try {
      console.log(`❤️ Removing product ${productId} from Firebase wishlist for ${customerEmail}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(customerId);
      const wishlistDoc = await wishlistRef.get();

      if (!wishlistDoc.exists) {
        console.log(`⚠️ No wishlist found for customer ${customerId}`);
        return { success: true, action: 'remove', productId, wishlistCount: 0, notFound: true };
      }

      const data = wishlistDoc.data();
      let items = data.items || [];

      // Remove item
      const originalLength = items.length;
      items = items.filter(item => item.productId !== productId);

      if (items.length === originalLength) {
        console.log(`⚠️ Product ${productId} not found in wishlist`);
        return { success: true, action: 'remove', productId, wishlistCount: items.length, notFound: true };
      }

      // Update Firestore
      await wishlistRef.set({
        customerId,
        customerEmail,
        items,
        updatedAt: new Date().toISOString(),
        createdAt: data.createdAt || new Date().toISOString()
      });

      console.log(`✅ Removed product ${productId} from Firebase wishlist. Total items: ${items.length}`);
      return { success: true, action: 'remove', productId, wishlistCount: items.length };

    } catch (error) {
      console.error('❌ Firebase remove from wishlist error:', error);
      throw error;
    }
  }

  // Sync Shopify wishlist to Firebase (migration helper)
  async syncFromShopify(customerId, customerEmail, shopifyWishlistItems) {
    try {
      console.log(`🔄 Syncing Shopify wishlist to Firebase for ${customerEmail}`);
      console.log(`📊 Shopify items to sync: ${shopifyWishlistItems.length}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(customerId);
      
      // Convert Shopify items to Firebase format
      const firebaseItems = shopifyWishlistItems.map(productId => ({
        productId,
        addedAt: new Date().toISOString(), // We don't have original dates from Shopify
        customerEmail,
        customerId,
        syncedFromShopify: true
      }));

      // Save to Firebase
      await wishlistRef.set({
        customerId,
        customerEmail,
        items: firebaseItems,
        syncedFromShopify: true,
        syncedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdAt: new Date().toISOString()
      });

      console.log(`✅ Successfully synced ${firebaseItems.length} wishlist items from Shopify to Firebase`);
      return { success: true, syncedItems: firebaseItems.length };

    } catch (error) {
      console.error('❌ Firebase sync from Shopify error:', error);
      throw error;
    }
  }

  // Get wishlist product IDs only (for compatibility with existing Shopify product fetching)
  async getWishlistProductIds(customerId, customerEmail) {
    try {
      const items = await this.getWishlist(customerId, customerEmail);
      return items.map(item => item.productId);
    } catch (error) {
      console.error('❌ Firebase get wishlist product IDs error:', error);
      throw error;
    }
  }

  // Health check - test Firebase connection
  async healthCheck() {
    try {
      // Simple connectivity test - just check if we can access Firestore
      const testRef = this.db.collection('health_check');
      await testRef.limit(1).get(); // Just try to query, don't write
      return { status: 'healthy', firebase: 'connected' };
    } catch (error) {
      console.error('❌ Firebase health check failed:', error);
      return { status: 'unhealthy', error: error.message };
    }
  }
}

module.exports = WishlistService;
