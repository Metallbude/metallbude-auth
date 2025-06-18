#!/usr/bin/env node

/**
 * Test script to verify the wishlist cache fix
 * This script tests the API responses to ensure they're correct
 */

const fetch = require('node-fetch');

// Configuration
const API_BASE = 'https://metallbude-auth.onrender.com';
const FIREBASE_CONFIG = require('./firebase-service-account.json');

// Test customer details
const TEST_EMAIL = 'rudi.mayr7@gmail.com';

async function testWishlistAPI() {
  console.log('🧪 Testing Wishlist API for Cache Fix Verification');
  console.log('=' .repeat(60));
  
  try {
    // Test 1: Check current wishlist
    console.log('\n1️⃣ Testing GET /api/wishlist...');
    
    const response = await fetch(`${API_BASE}/api/wishlist`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer test-token` // Use test auth for mobile endpoint
      }
    });
    
    console.log(`Status: ${response.status}`);
    
    if (response.ok) {
      const data = await response.json();
      console.log('✅ API Response successful');
      console.log(`📊 Response format: ${data.wishlist ? 'Object with wishlist array' : 'Direct array or other'}`);
      
      if (data.wishlist && Array.isArray(data.wishlist)) {
        console.log(`📱 Wishlist items count: ${data.wishlist.length}`);
        
        if (data.wishlist.length > 0) {
          console.log('\n📋 Wishlist items:');
          data.wishlist.forEach((item, index) => {
            console.log(`  ${index + 1}. ${item.title || item.id || 'Unknown'}`);
            console.log(`     ID: ${item.id}`);
            console.log(`     Price: ${item.priceRange?.minVariantPrice?.amount || 'N/A'}`);
          });
        } else {
          console.log('📱 Wishlist is empty');
        }
      } else {
        console.log('⚠️ Unexpected response format');
        console.log('Response:', JSON.stringify(data, null, 2));
      }
    } else {
      console.log('❌ API request failed');
      console.log('Response:', await response.text());
    }
    
    // Test 2: Check Firebase directly
    console.log('\n2️⃣ Testing Firebase directly...');
    
    const admin = require('firebase-admin');
    
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(FIREBASE_CONFIG),
        databaseURL: 'https://metallbude-app-default-rtdb.europe-west1.firebasedatabase.app/'
      });
    }
    
    const firestore = admin.firestore();
    
    // Query for customer by email
    const customersRef = firestore.collection('customers');
    const customerQuery = await customersRef.where('email', '==', TEST_EMAIL).get();
    
    if (!customerQuery.empty) {
      const customerDoc = customerQuery.docs[0];
      const customerId = customerDoc.id;
      const customerData = customerDoc.data();
      
      console.log(`✅ Found customer: ${customerId}`);
      console.log(`📧 Email: ${customerData.email}`);
      
      // Get wishlist
      const wishlistRef = firestore.collection('wishlists').doc(customerId);
      const wishlistDoc = await wishlistRef.get();
      
      if (wishlistDoc.exists) {
        const wishlistData = wishlistDoc.data();
        console.log(`📱 Firebase wishlist items: ${wishlistData.productIds?.length || 0}`);
        
        if (wishlistData.productIds && wishlistData.productIds.length > 0) {
          console.log('🔗 Product IDs in Firebase:');
          wishlistData.productIds.forEach((id, index) => {
            console.log(`  ${index + 1}. ${id}`);
          });
        }
      } else {
        console.log('📱 No wishlist document in Firebase');
      }
    } else {
      console.log('❌ Customer not found in Firebase');
    }
    
    console.log('\n✅ Cache fix test completed');
    console.log('\n📋 Summary:');
    console.log('- API should return the correct number of items');
    console.log('- Flutter app should clear local cache when API data is fetched');
    console.log('- Force refresh should always show latest backend data');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

if (require.main === module) {
  testWishlistAPI();
}

module.exports = { testWishlistAPI };
