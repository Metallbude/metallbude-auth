# 🛍️ Metallbude Wishlist System

A comprehensive wishlist system for Shopify stores with Firebase backend integration and beautiful, responsive UI.

## ✨ Features

- **🔥 Firebase Integration**: Real-time wishlist storage and synchronization
- **📱 Mobile-Optimized**: Perfect touch experience on all devices  
- **🎨 Beautiful UI**: Matches Metallbude's minimalist aesthetic
- **⚡ Instant Updates**: Smooth animations and immediate UI feedback
- **🔄 Bidirectional Sync**: Web ↔ Mobile app synchronization
- **🛡️ Secure**: Customer authentication and data protection
- **📊 Analytics Ready**: Built-in tracking and metrics

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Shopify Web   │    │  Node.js API    │    │    Firebase     │
│   + Flutter     │◄──►│   (Express)     │◄──►│   Firestore     │
│      App        │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        │                        │                        │
        ▼                        ▼                        ▼
   UI Interaction          API Endpoints           Data Storage
```

## 🚀 Quick Start

### 1. Environment Setup

```bash
npm install
cp .env.example .env
# Configure your environment variables
```

### 2. Firebase Configuration

```bash
# Add your Firebase service account key
firebase-service-account.json
```

### 3. Start the Server

```bash
npm start
# Server runs on http://localhost:3000
```

## 📁 Project Structure

```
metallbude_auth/
├── index.js                    # Main Express server
├── package.json               # Dependencies and scripts
├── services/                  # Core services
│   ├── firebase.js           # Firebase initialization
│   └── wishlist.js           # Wishlist logic
├── page.wishlist.liquid      # Shopify wishlist page
├── shopify-customer-script.liquid  # Customer integration
└── assets/                   # Static assets
```

## 🛠️ API Endpoints

### Public Endpoints

```http
GET  /api/public/wishlist/items?customerId={id}
POST /api/public/wishlist/add
POST /api/public/wishlist/remove
```

### Authenticated Endpoints

```http
GET  /api/wishlist/items
POST /api/wishlist/add
POST /api/wishlist/remove
```

## 🎨 Wishlist Page Features

- **🖼️ Product Cards**: Clean, Pinterest-style layout
- **🌈 Color Swatches**: Visual variant selection
- **💶 Price Display**: With sale prices and German formatting
- **🗑️ Smooth Removal**: Beautiful slide-out animations
- **📱 Touch Optimized**: Perfect mobile experience
- **🔄 Real-time Sync**: Instant updates across devices

## 🔧 Configuration

### Environment Variables

```env
PORT=3000
FIREBASE_PROJECT_ID=your-project-id
SHOPIFY_SHOP_DOMAIN=your-shop.myshopify.com
SHOPIFY_ACCESS_TOKEN=your-access-token
```

### Firebase Setup

1. Create a Firebase project
2. Enable Firestore
3. Download service account key
4. Place in `firebase-service-account.json`

## 📱 Mobile Integration

The system integrates seamlessly with Flutter apps:

```dart
final wishlistService = WishlistService();
await wishlistService.addToWishlist(product);
await wishlistService.removeFromWishlist(productId);
```

## 🎯 Key Components

### Wishlist Service (`services/wishlist.js`)
- Firebase Firestore integration
- ID normalization and matching
- Variant-specific operations
- Debug logging

### UI Manager (`page.wishlist.liquid`)
- Responsive grid layout
- Touch gesture handling
- Animation management
- Error handling

### API Server (`index.js`)
- Express.js REST API
- CORS configuration
- Customer authentication
- Shopify integration

## 🚀 Deployment

### Render.com (Recommended)

```bash
# Automatic deployment from GitHub
# Set environment variables in Render dashboard
```

### Manual Deployment

```bash
npm run build
npm start
```

## 🔍 Debugging

Enable debug logging:

```env
DEBUG=true
LOG_LEVEL=debug
```

Debug endpoints:
- `GET /api/debug/wishlist-customers`
- `GET /api/debug/firebase-status`

## 📊 Analytics Integration

Track wishlist events:

```javascript
analytics.track('Wishlist Item Added', {
  productId: product.id,
  variantId: variant.id,
  customerId: customer.id
});
```

## 🛡️ Security Features

- **🔐 Customer Authentication**: Secure session management
- **🛡️ Input Validation**: Sanitized data processing  
- **🔒 Firebase Rules**: Database-level security
- **🌐 CORS Protection**: Restricted domain access

## 🎨 Design System

Colors:
- **Background**: `#FCFBF9` (Metallbude Beige)
- **Text**: `#000000` (Pure Black)
- **Accent**: `#666666` (Medium Gray)
- **Success**: `#28a745` (Green)

Typography:
- **Font**: System font stack
- **Headings**: Uppercase, letter-spacing
- **Body**: Clean, readable hierarchy

## 📈 Performance

- **⚡ Fast Loading**: Optimized API calls
- **🗄️ Smart Caching**: Local and Firebase caching
- **📱 Mobile First**: Touch-optimized interactions
- **🔄 Offline Support**: Service worker ready

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

Proprietary - Metallbude GmbH

## 🆘 Support

For support and questions:
- 📧 Email: dev@metallbude.com
- 📱 Mobile: Check Flutter app integration
- 🌐 Web: Shopify admin panel

---

**Built with ❤️ for Metallbude**
