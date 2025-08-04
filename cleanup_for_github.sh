#!/bin/bash

# GitHub Cleanup Script for Metallbude Auth
# This script removes temporary files, debug files, and sensitive data before pushing to GitHub

echo "🧹 Cleaning up project for GitHub..."

# Remove debug and test files
echo "🗑️ Removing debug files..."
rm -f debug_*.js
rm -f test_*.js
rm -f check_*.js
rm -f find_*.js
rm -f analyze_*.js
rm -f inspect_*.js
rm -f investigate_*.js
rm -f update_*.js
rm -f search_*.js
rm -f final_*.js
rm -f fix_*.js
rm -f verify_*.js
rm -f list_*.js
rm -f cleanup_*.js

# Remove test HTML files
echo "🗑️ Removing test HTML files..."
rm -f test_*.html
rm -f mobile_*.html
rm -f cors_*.html

# Remove temporary files
echo "🗑️ Removing temporary files..."
rm -f *.tmp
rm -f *.temp
rm -f *.log
rm -f server.log

# Remove sensitive files (keep .env but it should be in .gitignore)
echo "🔒 Checking sensitive files..."
if [ -f ".env" ]; then
    echo "⚠️  .env file found - make sure it's in .gitignore"
fi

if [ -f "firebase-service-account.json" ]; then
    echo "⚠️  Firebase service account found - make sure it's in .gitignore"
fi

# Remove node_modules if present (should be in .gitignore anyway)
if [ -d "node_modules" ]; then
    echo "📦 node_modules found - make sure it's in .gitignore"
fi

# Create/update .gitignore
echo "📝 Creating/updating .gitignore..."
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Firebase
firebase-service-account.json
firebase-adminsdk-*.json

# Logs
*.log
server.log

# Debug and test files
debug_*.js
test_*.js
check_*.js
find_*.js
analyze_*.js
inspect_*.js
investigate_*.js
update_*.js
search_*.js
final_*.js
fix_*.js
verify_*.js
list_*.js
cleanup_*.js

# Test HTML files
test_*.html
mobile_*.html
cors_*.html

# Temporary files
*.tmp
*.temp

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Data files (local storage)
data/
EOF

echo "✅ Cleanup complete!"
echo ""
echo "📋 Files ready for GitHub:"
echo "   ✅ index.js (main server)"
echo "   ✅ package.json"
echo "   ✅ services/ (Firebase & Wishlist services)"
echo "   ✅ page.wishlist.liquid (wishlist page)"
echo "   ✅ shopify-customer-script.liquid (customer script)"
echo "   ✅ .gitignore (updated)"
echo ""
echo "🚀 Ready to push to GitHub!"
echo "   git add ."
echo "   git commit -m 'Add Metallbude wishlist system with Firebase integration'"
echo "   git push origin main"
