// Quick fix for wishlist file system issue on Render.com

// Replace the saveWishlistData function to handle filesystem errors gracefully
async function saveWishlistData(data) {
    try {
        const filePath = path.join(__dirname, 'wishlist_data.json');
        await fs.writeFile(filePath, JSON.stringify(data, null, 2));
        console.log('✅ [STORAGE] Successfully saved wishlist data to filesystem');
    } catch (error) {
        console.error('⚠️ [STORAGE] Error saving wishlist data to filesystem (continuing without persistent storage):', error.message);
        // Don't throw error - continue without persistent storage
        // The data will still be processed and sent to Firebase
    }
}

// Replace the loadWishlistData function to handle missing files gracefully
async function loadWishlistData() {
    try {
        const filePath = path.join(__dirname, 'wishlist_data.json');
        const data = await fs.readFile(filePath, 'utf8');
        console.log('✅ [STORAGE] Successfully loaded wishlist data from filesystem');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('ℹ️ [STORAGE] No wishlist data file found, starting with empty data');
            return {}; // Return empty object if file doesn't exist
        } else {
            console.error('⚠️ [STORAGE] Error reading wishlist data file (using empty data):', error.message);
            return {}; // Return empty object if any read error
        }
    }
}

console.log('🔧 Wishlist filesystem fix loaded');
