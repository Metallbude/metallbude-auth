const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');

// Initialize Firebase Admin SDK
let firebaseApp = null;
let isInitialized = false;

function initializeFirebase() {
  if (firebaseApp) {
    return firebaseApp;
  }

  try {
    let credential = null;
    
    // Method 1: Try environment variable (Production - Render.com)
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      console.log('🔥 Loading Firebase from environment variable (Production mode)');
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      credential = admin.credential.cert(serviceAccount);
    }
    // Method 2: Try individual environment variables
    else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
      console.log('🔥 Loading Firebase from individual environment variables');
      credential = admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      });
    }
    // Method 3: Try service account file (Development)
    else {
      const serviceAccountPath = path.join(__dirname, '..', 'firebase-service-account.json');
      if (fs.existsSync(serviceAccountPath)) {
        console.log('🔥 Loading Firebase from service account file (Development mode)');
        credential = admin.credential.cert(serviceAccountPath);
      } else {
        throw new Error('No Firebase credentials found. Please set environment variables or add firebase-service-account.json file.');
      }
    }

    // Initialize Firebase Admin SDK
    firebaseApp = admin.initializeApp({
      credential: credential,
      databaseURL: `https://${process.env.FIREBASE_PROJECT_ID || 'metallbude-mobile-app'}.firebaseio.com`
    });

    isInitialized = true;
    console.log('✅ Firebase Admin SDK initialized successfully');
    console.log(`🎯 Project: ${firebaseApp.options.projectId}`);
    
    return firebaseApp;
  } catch (error) {
    console.error('❌ Firebase initialization error:', error.message);
    console.log('⚠️ Firebase will be disabled - falling back to Shopify storage');
    throw error;
  }
}

// Get Firestore instance
function getFirestore() {
  const app = initializeFirebase();
  return admin.firestore(app);
}

// Check if Firebase is properly initialized
function isFirebaseReady() {
  return isInitialized && firebaseApp !== null;
}

// Get Firebase app instance
function getFirebaseApp() {
  return firebaseApp;
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
  isFirebaseReady,
  getFirebaseApp,
  COLLECTIONS,
  admin
};
