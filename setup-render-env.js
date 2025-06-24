#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

console.log('🔧 Metallbude Auth - Environment Setup Helper\n');

// Check if firebase-service-account.json exists
const firebaseServiceAccountPath = './firebase-service-account.json';

if (!fs.existsSync(firebaseServiceAccountPath)) {
  console.error('❌ firebase-service-account.json not found!');
  console.log('📋 Make sure you have:');
  console.log('   1. Downloaded the Firebase service account file');
  console.log('   2. Renamed it to "firebase-service-account.json"');
  console.log('   3. Placed it in the root directory of your project');
  process.exit(1);
}

try {
  // Read the Firebase service account file
  const serviceAccount = JSON.parse(fs.readFileSync(firebaseServiceAccountPath, 'utf8'));
  
  console.log('✅ Firebase service account file found');
  console.log('🔐 Preparing secure environment variables for Render.com...\n');
  
  // Generate a secure session secret
  const sessionSecret = crypto.randomBytes(32).toString('hex');
  
  console.log('=' .repeat(80));
  console.log('🚀 RENDER.COM ENVIRONMENT VARIABLES');
  console.log('=' .repeat(80));
  console.log('Copy each variable below to your Render.com dashboard:\n');
  
  // Essential environment variables
  const envVars = [
    { key: 'NODE_ENV', value: 'production' },
    { key: 'SESSION_SECRET', value: sessionSecret },
    { key: 'FIREBASE_SERVICE_ACCOUNT', value: JSON.stringify(serviceAccount) },
    { key: 'SERVER_URL', value: 'https://metallbude-auth.onrender.com' }
  ];
  
  envVars.forEach(({ key, value }) => {
    console.log(`🔑 Key: ${key}`);
    console.log(`📝 Value: ${value}`);
    console.log('-'.repeat(40));
  });
  
  console.log('\n📋 OPTIONAL VARIABLES (if not already set):');
  console.log('-'.repeat(40));
  console.log('🔑 Key: SHOPIFY_ADMIN_TOKEN');
  console.log('📝 Value: [Your Shopify Admin API token]');
  console.log('-'.repeat(40));
  console.log('🔑 Key: SHOPIFY_STOREFRONT_TOKEN');
  console.log('📝 Value: [Your Shopify Storefront API token]');
  console.log('-'.repeat(40));
  
  console.log('\n🔒 SECURITY REMINDERS:');
  console.log('=' .repeat(50));
  console.log('✅ firebase-service-account.json is in .gitignore');
  console.log('✅ Environment variables are secure in Render dashboard');
  console.log('❌ NEVER commit the firebase-service-account.json file');
  console.log('❌ NEVER share these environment variable values');
  console.log('❌ NEVER post these values in chat/email/forums');
  
  console.log('\n🚀 NEXT STEPS:');
  console.log('=' .repeat(30));
  console.log('1. Go to your Render.com dashboard');
  console.log('2. Select your metallbude-auth service');
  console.log('3. Go to the "Environment" tab');
  console.log('4. Add each environment variable listed above');
  console.log('5. Save changes and redeploy');
  console.log('6. Test: https://metallbude-auth.onrender.com/health');
  
  console.log('\n🎯 SUCCESS CRITERIA:');
  console.log('- Health endpoint shows "firebase: connected"');
  console.log('- No errors in Render service logs');
  console.log('- Wishlist API endpoints working correctly');
  
} catch (error) {
  console.error('❌ Error reading Firebase service account file:', error.message);
  console.log('\n🔧 Troubleshooting:');
  console.log('1. Make sure the file is valid JSON');
  console.log('2. Check file permissions');
  console.log('3. Re-download from Firebase Console if corrupted');
  process.exit(1);
}

console.log('\n✨ Setup complete! Your server is ready for secure deployment.');
