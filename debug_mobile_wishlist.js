#!/usr/bin/env node

const axios = require('axios');

const BACKEND_URL = process.env.BACKEND_URL || 'https://metallbude-auth.onrender.com';

async function testMobileEndpoints() {
  console.log('🔍 Testing Mobile Wishlist Endpoints');
  console.log('='.repeat(50));
  
  const testCustomerId = '4088060379300';
  
  // Test 1: Direct API call to load wishlist
  console.log('\n📱 Test 1: Load Wishlist API');
  try {
    const response = await axios.get(`${BACKEND_URL}/api/public/wishlist/items?customerId=${testCustomerId}`, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15'
      }
    });
    
    console.log('   Status:', response.status);
    console.log('   Data:', JSON.stringify(response.data, null, 2));
    console.log(`   Items count: ${response.data.items ? response.data.items.length : 'N/A'}`);
  } catch (error) {
    console.error('   Error:', error.response ? `${error.response.status} - ${error.response.statusText}` : error.message);
    if (error.response) {
      console.error('   Response data:', error.response.data);
    }
  }
  
  // Test 2: Test with different mobile user agents
  console.log('\n📱 Test 2: Different Mobile User Agents');
  const userAgents = [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1'
  ];
  
  for (const ua of userAgents) {
    try {
      const response = await axios.get(`${BACKEND_URL}/api/public/wishlist/items?customerId=${testCustomerId}`, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': ua
        }
      });
      
      console.log(`   ${ua.split(')')[0]}) - Status: ${response.status}`);
      console.log(`     Items: ${response.data.items ? response.data.items.length : 'N/A'}`);
    } catch (error) {
      console.log(`     Error: ${error.response ? error.response.status : error.message}`);
    }
  }
  
  // Test 3: Test with CORS preflight
  console.log('\n📱 Test 3: CORS Preflight (OPTIONS)');
  try {
    const response = await axios.options(`${BACKEND_URL}/api/public/wishlist/${testCustomerId}`, {
      headers: {
        'Origin': 'https://metallbude.com',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Content-Type'
      }
    });
    
    console.log('   Status:', response.status);
    console.log('   CORS Headers:', {
      'Access-Control-Allow-Origin': response.headers['access-control-allow-origin'],
      'Access-Control-Allow-Methods': response.headers['access-control-allow-methods'],
      'Access-Control-Allow-Headers': response.headers['access-control-allow-headers']
    });
  } catch (error) {
    console.error('   Error:', error.response ? `${error.response.status} - ${error.response.statusText}` : error.message);
  }
  
  // Test 4: Check server health
  console.log('\n📱 Test 4: Server Health');
  try {
    const response = await axios.get(`${BACKEND_URL}/health`);
    
    console.log('   Status:', response.status);
    console.log('   Response:', response.data);
  } catch (error) {
    console.error('   Error:', error.response ? `${error.response.status} - ${error.response.statusText}` : error.message);
  }
  
  console.log('\n' + '='.repeat(50));
  console.log('✅ Mobile debugging test complete');
}

testMobileEndpoints().catch(console.error);
