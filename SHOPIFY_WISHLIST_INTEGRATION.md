# Shopify Wishlist Integration Guide

This guide explains how to integrate the Firebase-based wishlist system with your Shopify theme.

## Files Required

1. **Backend**: Your Node.js backend is already set up and deployed on Render
2. **Frontend**: Shopify theme template file (see below)

## Implementation Steps

### 1. Create Wishlist Page Template

Create a new file in your Shopify theme: `templates/page.wishlist.liquid`

Use the content from either:
- `firebase-wishlist-template.liquid` (Advanced version with Storefront API)
- `simple-wishlist-template.liquid` (Recommended - uses Ajax API)

### 2. Create Wishlist Page in Shopify Admin

1. Go to Shopify Admin → Online Store → Pages
2. Create a new page called "Wishlist" or "Wunschliste"
3. Set the template to "page.wishlist"
4. Save the page

### 3. Add Wishlist Navigation

Add a link to your wishlist page in your theme's navigation:

```liquid
<a href="{{ pages.wishlist.url }}">Wunschliste</a>
```

### 4. Add Wishlist Buttons to Product Pages

Add wishlist add/remove buttons to your product templates:

```liquid
<!-- In templates/product.liquid or sections/product-form.liquid -->
<button id="wishlist-btn-{{ product.id }}" 
        onclick="toggleWishlist('{{ product.id | prepend: 'gid://shopify/Product/' }}')"
        class="wishlist-button">
  <span class="add-text">Zur Wunschliste hinzufügen</span>
  <span class="remove-text" style="display: none;">Von Wunschliste entfernen</span>
</button>

<script>
async function toggleWishlist(productId) {
  const customerId = '{{ customer.id }}';
  if (!customerId) {
    alert('Bitte melde dich an, um Produkte zur Wunschliste hinzuzufügen.');
    window.location.href = '{{ routes.account_login_url }}';
    return;
  }

  const button = document.getElementById('wishlist-btn-{{ product.id }}');
  const addText = button.querySelector('.add-text');
  const removeText = button.querySelector('.remove-text');
  
  try {
    // Check if product is in wishlist
    const checkResponse = await fetch(`https://metallbude-auth.onrender.com/api/public/wishlist/items?customerId=${customerId}`);
    const checkData = await checkResponse.json();
    
    const isInWishlist = checkData.success && checkData.items && 
                        checkData.items.some(item => item.productId === productId);
    
    if (isInWishlist) {
      // Remove from wishlist
      const response = await fetch('https://metallbude-auth.onrender.com/api/public/wishlist/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ customerId, productId })
      });
      
      if (response.ok) {
        addText.style.display = 'inline';
        removeText.style.display = 'none';
        button.classList.remove('in-wishlist');
      }
    } else {
      // Add to wishlist
      const response = await fetch('https://metallbude-auth.onrender.com/api/public/wishlist/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ customerId, productId })
      });
      
      if (response.ok) {
        addText.style.display = 'none';
        removeText.style.display = 'inline';
        button.classList.add('in-wishlist');
      }
    }
  } catch (error) {
    console.error('Wishlist error:', error);
    alert('Fehler beim Aktualisieren der Wunschliste');
  }
}

// Initialize button state on page load
document.addEventListener('DOMContentLoaded', async function() {
  const customerId = '{{ customer.id }}';
  const productId = '{{ product.id | prepend: "gid://shopify/Product/" }}';
  
  if (customerId) {
    try {
      const response = await fetch(`https://metallbude-auth.onrender.com/api/public/wishlist/items?customerId=${customerId}`);
      const data = await response.json();
      
      if (data.success && data.items && data.items.some(item => item.productId === productId)) {
        const button = document.getElementById('wishlist-btn-{{ product.id }}');
        button.querySelector('.add-text').style.display = 'none';
        button.querySelector('.remove-text').style.display = 'inline';
        button.classList.add('in-wishlist');
      }
    } catch (error) {
      console.error('Error checking wishlist status:', error);
    }
  }
});
</script>

<style>
.wishlist-button {
  background: #f8f9fa;
  border: 1px solid #ddd;
  padding: 10px 15px;
  border-radius: 4px;
  cursor: pointer;
  margin: 10px 0;
  transition: all 0.2s;
}

.wishlist-button:hover {
  background: #e9ecef;
}

.wishlist-button.in-wishlist {
  background: #e74c3c;
  color: white;
  border-color: #c0392b;
}

.wishlist-button.in-wishlist:hover {
  background: #c0392b;
}
</style>
```

## How It Works

### Backend Integration

1. **Customer ID Mapping**: The system automatically converts Shopify customer IDs to Firebase-compatible document IDs
2. **Data Synchronization**: Both Flutter app and Shopify website read/write to the same Firebase collection
3. **CORS Configuration**: Backend is configured to allow requests from `https://metallbude.com`

### Frontend Integration

1. **Product ID Format**: Uses Shopify's GID format (`gid://shopify/Product/123`) for consistency
2. **Authentication**: Checks if user is logged in before allowing wishlist operations
3. **Error Handling**: Graceful fallbacks for missing products or network errors
4. **Real-time Updates**: Wishlist page refreshes after add/remove operations

## API Endpoints Used

- `GET /api/public/wishlist/items?customerId=123` - Get customer's wishlist
- `POST /api/public/wishlist/add` - Add product to wishlist
- `POST /api/public/wishlist/remove` - Remove product from wishlist

## Troubleshooting

### Common Issues

1. **"Unbekanntes Produkt"**: This was the original issue - fixed by fetching product details from Shopify's API
2. **CORS Errors**: Ensure your domain is whitelisted in the backend CORS configuration
3. **Customer Not Logged In**: Handle authentication gracefully with redirects to login page
4. **Product Not Found**: Some products might be deleted - handle with fallback display

### Debug Information

The wishlist templates include console logging for debugging:
- Check browser console for API request/response details
- Backend logs show customer ID mapping and Firebase operations
- Network tab shows CORS and API call status

### Backend Configuration

Make sure these environment variables are set on Render:
- `FIREBASE_SERVICE_ACCOUNT`: Your Firebase service account JSON
- `CORS_ORIGIN`: Should include `https://metallbude.com`

## Testing

1. **Flutter App**: Test add/remove/fetch operations
2. **Shopify Website**: Test the same operations from the browser
3. **Cross-Platform**: Add items in Flutter, verify they appear on Shopify website
4. **Edge Cases**: Test with logged-out users, deleted products, network errors

## Next Steps

1. **Style Integration**: Match the wishlist page styling to your theme
2. **Product Variants**: Consider supporting product variants in wishlist
3. **Anonymous Wishlists**: Optionally support wishlists for non-logged-in users
4. **Performance**: Consider caching product details for better performance
5. **Analytics**: Track wishlist usage for business insights
