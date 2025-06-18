#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔒 Metallbude Auth - Security Validation\n');

let securityScore = 0;
let totalChecks = 0;
const issues = [];
const warnings = [];

function checkPassed(message) {
  console.log(`✅ ${message}`);
  securityScore++;
}

function checkFailed(message, isWarning = false) {
  if (isWarning) {
    console.log(`⚠️  ${message}`);
    warnings.push(message);
  } else {
    console.log(`❌ ${message}`);
    issues.push(message);
  }
}

function runCheck(description, checkFunction) {
  totalChecks++;
  console.log(`\n🔍 ${description}`);
  checkFunction();
}

// Check 1: Firebase Service Account File Security
runCheck('Firebase Service Account File', () => {
  const firebaseFile = './firebase-service-account.json';
  
  if (!fs.existsSync(firebaseFile)) {
    checkFailed('firebase-service-account.json not found - Firebase will be disabled', true);
    return;
  }
  
  checkPassed('firebase-service-account.json exists');
  
  try {
    const stats = fs.statSync(firebaseFile);
    const mode = stats.mode & parseInt('777', 8);
    
    if (mode === parseInt('600', 8)) {
      checkPassed('File permissions are secure (600)');
    } else {
      checkFailed(`File permissions are ${mode.toString(8)}, should be 600`);
    }
  } catch (error) {
    checkFailed(`Cannot check file permissions: ${error.message}`);
  }
});

// Check 2: .gitignore Configuration
runCheck('Git Security (.gitignore)', () => {
  const gitignoreFile = './.gitignore';
  
  if (!fs.existsSync(gitignoreFile)) {
    checkFailed('.gitignore file missing');
    return;
  }
  
  const gitignoreContent = fs.readFileSync(gitignoreFile, 'utf8');
  
  const requiredEntries = [
    'firebase-service-account.json',
    '.env',
    'node_modules/',
    '*.log'
  ];
  
  requiredEntries.forEach(entry => {
    if (gitignoreContent.includes(entry)) {
      checkPassed(`${entry} is in .gitignore`);
    } else {
      checkFailed(`${entry} missing from .gitignore`);
    }
  });
});

// Check 3: Environment Variables
runCheck('Environment Variables', () => {
  const requiredEnvVars = [
    'NODE_ENV',
    'SESSION_SECRET'
  ];
  
  const recommendedEnvVars = [
    'SHOPIFY_ADMIN_TOKEN',
    'SHOPIFY_STOREFRONT_TOKEN',
    'SERVER_URL'
  ];
  
  requiredEnvVars.forEach(envVar => {
    if (process.env[envVar]) {
      checkPassed(`${envVar} is set`);
    } else {
      checkFailed(`${envVar} environment variable missing`);
    }
  });
  
  recommendedEnvVars.forEach(envVar => {
    if (process.env[envVar]) {
      checkPassed(`${envVar} is set`);
    } else {
      checkFailed(`${envVar} environment variable missing (recommended)`, true);
    }
  });
});

// Check 4: Package.json Security
runCheck('Package Dependencies', () => {
  const packageFile = './package.json';
  
  if (!fs.existsSync(packageFile)) {
    checkFailed('package.json not found');
    return;
  }
  
  const packageJson = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
  
  const requiredDeps = [
    'express',
    'cors',
    'firebase-admin',
    'jsonwebtoken'
  ];
  
  requiredDeps.forEach(dep => {
    if (packageJson.dependencies && packageJson.dependencies[dep]) {
      checkPassed(`${dep} dependency found`);
    } else {
      checkFailed(`${dep} dependency missing`);
    }
  });
});

// Check 5: File Structure
runCheck('Project File Structure', () => {
  const requiredFiles = [
    './services/firebase.js',
    './services/wishlist.js',
    './index.js',
    './package.json'
  ];
  
  const recommendedFiles = [
    './.env.template',
    './RENDER_DEPLOYMENT.md',
    './setup-render-env.js'
  ];
  
  requiredFiles.forEach(file => {
    if (fs.existsSync(file)) {
      checkPassed(`${file} exists`);
    } else {
      checkFailed(`${file} missing`);
    }
  });
  
  recommendedFiles.forEach(file => {
    if (fs.existsSync(file)) {
      checkPassed(`${file} exists`);
    } else {
      checkFailed(`${file} missing (recommended)`, true);
    }
  });
});

// Check 6: Git Repository Status
runCheck('Git Repository Security', () => {
  try {
    const { execSync } = require('child_process');
    
    // Check if firebase-service-account.json is tracked by git
    try {
      const trackedFiles = execSync('git ls-files', { encoding: 'utf8' });
      
      if (trackedFiles.includes('firebase-service-account.json')) {
        checkFailed('firebase-service-account.json is tracked by git - SECURITY RISK!');
      } else {
        checkPassed('firebase-service-account.json is not tracked by git');
      }
      
      if (trackedFiles.includes('.env')) {
        checkFailed('.env file is tracked by git - SECURITY RISK!');
      } else {
        checkPassed('.env file is not tracked by git');
      }
      
    } catch (error) {
      checkFailed('Cannot check git status - make sure you are in a git repository', true);
    }
    
  } catch (error) {
    checkFailed('Git not available or not in a git repository', true);
  }
});

// Final Report
console.log('\n' + '='.repeat(60));
console.log('🔒 SECURITY VALIDATION REPORT');
console.log('='.repeat(60));

const successRate = Math.round((securityScore / totalChecks) * 100);
console.log(`📊 Security Score: ${securityScore}/${totalChecks} (${successRate}%)`);

if (issues.length > 0) {
  console.log('\n🚨 CRITICAL ISSUES:');
  issues.forEach(issue => console.log(`   ❌ ${issue}`));
}

if (warnings.length > 0) {
  console.log('\n⚠️  WARNINGS:');
  warnings.forEach(warning => console.log(`   ⚠️  ${warning}`));
}

console.log('\n🎯 RECOMMENDATIONS:');
if (successRate >= 90) {
  console.log('✅ Excellent! Your security configuration is very good.');
} else if (successRate >= 75) {
  console.log('👍 Good security setup, but please address the issues above.');
} else if (successRate >= 50) {
  console.log('⚠️  Security needs improvement. Please fix critical issues.');
} else {
  console.log('🚨 Security configuration needs immediate attention!');
}

console.log('\n📚 For detailed deployment instructions, see:');
console.log('   📄 RENDER_DEPLOYMENT.md');
console.log('   🔧 Run: node setup-render-env.js');

process.exit(issues.length > 0 ? 1 : 0);
