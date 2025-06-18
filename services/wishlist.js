const { getFirestore, COLLECTIONS } = require('./firebase');

class WishlistService {
  constructor() {
    this.db = getFirestore();
  }

  // Sanitize customer ID for Firestore (remove invalid characters)
  _sanitizeCustomerId(customerId) {
    // Convert Shopify GID to valid Firestore document ID
    // gid://shopify/Customer/4088060379300 -> shopify_Customer_4088060379300
    return customerId.replace(/[\/\:]/g, '_').replace(/^gid_+/, '');
  }

  // Get customer's wishlist
  async getWishlist(customerId, customerEmail) {
    try {
      console.log(`🔥 [FIREBASE] Fetching wishlist for customer: ${customerEmail} (${customerId})`);

      // Ensure Firebase is properly initialized
      if (!this.db) {
        throw new Error('Firebase Firestore not initialized');
      }

      // Sanitize customer ID for Firestore document path
      const sanitizedCustomerId = this._sanitizeCustomerId(customerId);
      console.log(`🔥 [FIREBASE] Using sanitized document ID: ${sanitizedCustomerId}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(sanitizedCustomerId);
      const wishlistDoc = await wishlistRef.get();

      if (!wishlistDoc.exists) {
        console.log(`� [FIREBASE] No wishlist document found for customer ${customerId}, returning empty list`);
        return [];
      }

      const wishlistData = wishlistDoc.data();
      const items = wishlistData.items || [];

      console.log(`🔥 [FIREBASE] Found ${items.length} items in Firebase wishlist for ${customerEmail}`);
      return items.map(item => ({
        productId: item.productId,
        addedAt: item.addedAt,
        customerEmail: customerEmail,
        customerId: customerId,
        variantId: item.variantId || null,
        selectedOptions: item.selectedOptions || null
      }));

    } catch (error) {
      console.error('🔥 [FIREBASE] Wishlist fetch error:', error.message, error.stack);
      throw error;
    }
  }

  // Add product to wishlist
  async addToWishlist(customerId, customerEmail, productId, variantId = null, selectedOptions = null) {
    try {
      console.log(`🔥 [FIREBASE] Adding product ${productId} to wishlist for ${customerEmail} (${customerId})`);
      console.log(`🔥 [FIREBASE] Variant ID: ${variantId}, Selected Options:`, selectedOptions);

      // Ensure Firebase is properly initialized
      if (!this.db) {
        throw new Error('Firebase Firestore not initialized');
      }

      // Sanitize customer ID for Firestore document path
      const sanitizedCustomerId = this._sanitizeCustomerId(customerId);
      console.log(`🔥 [FIREBASE] Using sanitized document ID: ${sanitizedCustomerId}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(sanitizedCustomerId);
      const wishlistDoc = await wishlistRef.get();

      let items = [];
      if (wishlistDoc.exists) {
        const data = wishlistDoc.data();
        items = data.items || [];
      }

      // Check if item already exists with same variant/options
      const existingItemIndex = items.findIndex(item => {
        if (item.productId !== productId) return false;
        
        // If we have variant information, match by variant
        if (variantId && item.variantId) {
          return item.variantId === variantId;
        }
        
        // If we have selected options, match by options
        if (selectedOptions && item.selectedOptions) {
          return JSON.stringify(item.selectedOptions) === JSON.stringify(selectedOptions);
        }
        
        // Otherwise match by product ID only (backward compatibility)
        return !item.variantId && !item.selectedOptions;
      });
      
      if (existingItemIndex !== -1) {
        console.log(`🔥 [FIREBASE] Product ${productId} with variant/options already in wishlist for ${customerEmail}`);
        return { success: true, action: 'add', productId, wishlistCount: items.length, alreadyExists: true };
      }

      // Add new item with variant information
      const newItem = {
        productId,
        addedAt: new Date().toISOString(),
        customerEmail,
        customerId
      };
      
      // Add variant information if available
      if (variantId) {
        newItem.variantId = variantId;
      }
      if (selectedOptions && Object.keys(selectedOptions).length > 0) {
        newItem.selectedOptions = selectedOptions;
      }

      items.push(newItem);

      // Update Firestore
      await wishlistRef.set({
        customerId,
        customerEmail,
        items,
        updatedAt: new Date().toISOString(),
        createdAt: wishlistDoc.exists ? (wishlistDoc.data().createdAt || new Date().toISOString()) : new Date().toISOString()
      });

      console.log(`🔥 [FIREBASE] Successfully added product ${productId} to wishlist for ${customerEmail}. Total items: ${items.length}`);
      return { success: true, action: 'add', productId, wishlistCount: items.length };

    } catch (error) {
      console.error('🔥 [FIREBASE] Add to wishlist error:', error.message, error.stack);
      throw error;
    }
  }

  // Remove product from wishlist
  async removeFromWishlist(customerId, customerEmail, productId, variantId = null, selectedOptions = null) {
    try {
      console.log(`🔥 [FIREBASE] Removing product ${productId} from wishlist for ${customerEmail} (${customerId})`);
      console.log(`🔥 [FIREBASE] Variant ID: ${variantId}, Selected Options:`, selectedOptions);

      // Ensure Firebase is properly initialized
      if (!this.db) {
        throw new Error('Firebase Firestore not initialized');
      }

      // Sanitize customer ID for Firestore document path
      const sanitizedCustomerId = this._sanitizeCustomerId(customerId);
      console.log(`🔥 [FIREBASE] Using sanitized document ID: ${sanitizedCustomerId}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(sanitizedCustomerId);
      const wishlistDoc = await wishlistRef.get();

      if (!wishlistDoc.exists) {
        console.log(`🔥 [FIREBASE] No wishlist found for customer ${customerId}, nothing to remove`);
        return { success: true, action: 'remove', productId, wishlistCount: 0, notFound: true };
      }

      const data = wishlistDoc.data();
      let items = data.items || [];

      // Find and remove the matching item with variant/options
      const initialCount = items.length;
      items = items.filter(item => {
        if (item.productId !== productId) return true;
        
        // If we have variant information, match by variant
        if (variantId && item.variantId) {
          return item.variantId !== variantId;
        }
        
        // If we have selected options, match by options
        if (selectedOptions && item.selectedOptions) {
          return JSON.stringify(item.selectedOptions) !== JSON.stringify(selectedOptions);
        }
        
        // Otherwise remove by product ID only (backward compatibility)
        return item.variantId || item.selectedOptions;
      });
      const finalCount = items.length;

      if (initialCount === finalCount) {
        console.log(`🔥 [FIREBASE] Product ${productId} was not in wishlist for ${customerEmail}`);
        return { success: true, action: 'remove', productId, wishlistCount: finalCount, notFound: true };
      }

      // Update Firestore
      await wishlistRef.set({
        ...data,
        items,
        updatedAt: new Date().toISOString()
      });

      console.log(`🔥 [FIREBASE] Successfully removed product ${productId} from wishlist for ${customerEmail}. Remaining items: ${finalCount}`);
      return { success: true, action: 'remove', productId, wishlistCount: finalCount };

    } catch (error) {
      console.error('🔥 [FIREBASE] Remove from wishlist error:', error.message, error.stack);
      throw error;
    }
  }

  // Sync Shopify wishlist to Firebase (migration helper)
  async syncFromShopify(customerId, customerEmail, shopifyWishlistItems) {
    try {
      console.log(`🔄 Syncing Shopify wishlist to Firebase for ${customerEmail}`);
      console.log(`📊 Shopify items to sync: ${shopifyWishlistItems.length}`);

      // Sanitize customer ID for Firestore document path
      const sanitizedCustomerId = this._sanitizeCustomerId(customerId);
      console.log(`🔥 [FIREBASE] Using sanitized document ID: ${sanitizedCustomerId}`);

      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(sanitizedCustomerId);
      
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
      console.log(`🔍 [DEBUG] Getting wishlist product IDs for ${customerEmail} (${customerId})`);
      const items = await this.getWishlist(customerId, customerEmail);
      console.log(`🔍 [DEBUG] Raw items from getWishlist:`, JSON.stringify(items, null, 2));
      const productIds = items.map(item => item.productId);
      console.log(`🔍 [DEBUG] Extracted product IDs:`, productIds);
      return productIds;
    } catch (error) {
      console.error('❌ Firebase get wishlist product IDs error:', error);
      throw error;
    }
  }

  // Check if wishlist document exists (distinct from empty wishlist)
  async wishlistExists(customerId) {
    try {
      const sanitizedCustomerId = this._sanitizeCustomerId(customerId);
      const wishlistRef = this.db.collection(COLLECTIONS.WISHLISTS).doc(sanitizedCustomerId);
      const wishlistDoc = await wishlistRef.get();
      return wishlistDoc.exists;
    } catch (error) {
      console.error('🔥 [FIREBASE] Error checking wishlist existence:', error.message);
      return false;
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
