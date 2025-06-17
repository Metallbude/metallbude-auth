const admin = require('firebase-admin');
const path = require('path');

// Initialize Firebase Admin SDK
let firebaseApp = null;

function initializeFirebase() {
  if (firebaseApp) {
    return firebaseApp;
  }

  try {
    // Path to your service account key file
    const serviceAccountPath = path.join(__dirname, '..', 'firebase-service-account.json');
    
    // Check if running in production (using environment variables)
    if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY) {
      firebaseApp = admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        }),
        databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`
      });
    } else {
      // Use service account file for local development
      firebaseApp = admin.initializeApp({
        credential: admin.credential.cert(serviceAccountPath),
        databaseURL: `https://metallbude-mobile-app.firebaseio.com`
      });
    }

    console.log('✅ Firebase Admin SDK initialized successfully');
    return firebaseApp;
  } catch (error) {
    console.error('❌ Firebase initialization error:', error.message);
    throw error;
  }
}

// Get Firestore instance
function getFirestore() {
  const app = initializeFirebase();
  return admin.firestore(app);
}

// Collections
const COLLECTIONS = {
  WISHLISTS: 'wishlists',
  WISHLIST_ITEMS: 'wishlist_items',
  CUSTOMERS: 'customers'
};

module.exports = {
  initializeFirebase,
  getFirestore,
  COLLECTIONS,
  admin
};
