// Metallbude Wishlist Button for Product Pages
// Handles adding/removing specific variants to/from wishlist with instant sync

class MetallbudeWishlistButton {
  constructor() {
    // Always use production URL for consistency
    this.backendUrl = 'https://metallbude-auth.onrender.com';
    this.customerId = this.getCustomerId();
    this.init();
  }

  getCustomerId() {
    console.log('🔍 Detecting customer ID...');
    console.log('🔍 Available global objects:', {
      ShopifyCustomer: typeof window.ShopifyCustomer,
      meta: typeof window.meta,
      theme: typeof window.theme,
      Shopify: typeof window.Shopify
    });
    
    // Enhanced debugging for customer detection
    console.log('🔍 Full ShopifyCustomer object:', window.ShopifyCustomer);
    console.log('🔍 Current URL:', window.location.href);
    console.log('🔍 Document cookies:', document.cookie);
    
    // Check if customer is logged in via Shopify Customer object
    if (typeof window.ShopifyCustomer !== 'undefined' && window.ShopifyCustomer && window.ShopifyCustomer.id) {
      const customerId = window.ShopifyCustomer.id.toString();
      console.log('🔍 Found Shopify customer:', customerId);
      return customerId;
    }
    
    // Check for customer info in page content - look for customer data in script tags
    const scripts = document.querySelectorAll('script');
    for (const script of scripts) {
      if (script.textContent) {
        // Look for customer ID patterns in script content
        const customerMatch = script.textContent.match(/customer.*?id["']?\s*:\s*["']?(\d+)["']?/i);
        if (customerMatch) {
          console.log('🔍 Found customer ID in script:', customerMatch[1]);
          return customerMatch[1];
        }
        
        // Look for Shopify customer object
        const shopifyMatch = script.textContent.match(/["']customer["']:\s*\{[^}]*["']id["']:\s*["']?(\d+)["']?/i);
        if (shopifyMatch) {
          console.log('🔍 Found customer ID in Shopify object:', shopifyMatch[1]);
          return shopifyMatch[1];
        }
      }
    }
    
    // For Liquid template integration - check for customer script tag
    const customerScript = document.querySelector('script[data-customer-id]');
    if (customerScript) {
      const customerId = customerScript.getAttribute('data-customer-id');
      console.log('🔍 Found customer ID from script tag:', customerId);
      return customerId;
    }
    
    // Check for customer info in Shopify global meta object
    if (typeof window.meta !== 'undefined' && window.meta.customer && window.meta.customer.id) {
      const customerId = window.meta.customer.id.toString();
      console.log('🔍 Found customer in meta:', customerId);
      return customerId;
    }
    
    // Check for customer info in theme settings
    if (typeof window.theme !== 'undefined' && window.theme.customer && window.theme.customer.id) {
      const customerId = window.theme.customer.id.toString();
      console.log('🔍 Found customer in theme:', customerId);
      return customerId;
    }
    
    // Check for logged-in customer in Shopify's global object
    if (typeof window.Shopify !== 'undefined' && window.Shopify.customer && window.Shopify.customer.id) {
      const customerId = window.Shopify.customer.id.toString();
      console.log('🔍 Found customer in Shopify global:', customerId);
      return customerId;
    }
    
    // Check if we can extract customer ID from page content/forms
    const customerIdInput = document.querySelector('input[name="customer_id"], input[data-customer-id]');
    if (customerIdInput && customerIdInput.value) {
      const customerId = customerIdInput.value;
      console.log('🔍 Found customer ID from input:', customerId);
      return customerId;
    }
    
    // Check meta tags for customer info
    const customerMeta = document.querySelector('meta[name="customer-id"], meta[property="customer-id"]');
    if (customerMeta) {
      const customerId = customerMeta.getAttribute('content');
      console.log('🔍 Found customer ID from meta tag:', customerId);
      return customerId;
    }
    
    // Look for customer ID in URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const customerIdParam = urlParams.get('customer_id') || urlParams.get('customerId');
    if (customerIdParam) {
      console.log('🔍 Found customer ID from URL param:', customerIdParam);
      return customerIdParam;
    }
    
    console.log('🔍 No customer ID found, checking if user is logged in...');
    
    // Check if user appears to be logged in by looking for account-related elements
    const accountLinks = document.querySelectorAll('a[href*="/account"], a[href*="/orders"], .account-link, .customer-name');
    if (accountLinks.length > 0) {
      console.log('🔍 User appears to be logged in (found account links), but no customer ID detected');
      console.log('🔍 Account links found:', accountLinks.length);
      
      // Try to extract customer ID from account link if it contains it
      for (const link of accountLinks) {
        const href = link.getAttribute('href');
        if (href) {
          const customerMatch = href.match(/customer[/_](\d+)/i);
          if (customerMatch) {
            console.log('🔍 Found customer ID in account link:', customerMatch[1]);
            return customerMatch[1];
          }
        }
      }
    }
    
    // Fallback: generate temporary guest ID
    let guestId = localStorage.getItem('metallbude_guest_id');
    if (!guestId) {
      guestId = 'guest_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      localStorage.setItem('metallbude_guest_id', guestId);
    }
    console.log('🔍 Using guest ID:', guestId);
    return guestId;
  }

  init() {
    console.log('🔥 Metallbude Wishlist Button initialized');
    console.log('🆔 Customer ID:', this.customerId);
    console.log('🌐 Backend URL:', this.backendUrl);
    
    this.setupEventListeners();
    
    // Initialize buttons after a short delay to ensure DOM is ready
    setTimeout(() => {
      this.initializeButtons();
    }, 100);
  }

  setupEventListeners() {
    // Handle wishlist button clicks - support both classes
    document.addEventListener('click', (e) => {
      const wishlistBtn = e.target.closest('.metallbude-wishlist-btn, .wishlist-btn');
      if (wishlistBtn) {
        e.preventDefault();
        e.stopPropagation();
        this.handleWishlistClick(wishlistBtn);
      }
    });

    // ✅ ENHANCED: Handle variant changes to update button state immediately
    document.addEventListener('change', (e) => {
      console.log('🔄 Change event detected:', e.target);
      
      // Check for various variant selector types
      if (e.target.name === 'id' || 
          e.target.classList.contains('variant-selector') ||
          e.target.getAttribute('data-option') ||
          e.target.getAttribute('data-option-name') ||
          e.target.name.includes('option') ||
          e.target.closest('.option-selector')) {
        
        console.log('🔄 Variant/option change detected, updating button states...');
        // Small delay to ensure DOM is updated
        setTimeout(() => {
          this.updateButtonStates();
        }, 50);
      }
    });

    // ✅ ENHANCED: Listen for radio button clicks (immediate feedback)
    document.addEventListener('click', (e) => {
      if (e.target.type === 'radio' && 
          (e.target.getAttribute('data-option') || 
           e.target.getAttribute('data-option-name') ||
           e.target.name.includes('option'))) {
        
        console.log('🔄 Radio option click detected, updating button states...');
        // Immediate update for radio buttons
        setTimeout(() => {
          this.updateButtonStates();
        }, 10);
      }
    });

    // Listen for custom variant change events from Shopify themes
    document.addEventListener('variantChanged', (e) => {
      console.log('🔄 Custom variantChanged event detected:', e.detail);
      this.updateButtonStates();
    });

    // Listen for Shopify's variant change events
    document.addEventListener('variant:change', (e) => {
      console.log('🔄 Shopify variant:change event detected:', e.detail);
      this.updateButtonStates();
    });

    // Listen for product form updates
    document.addEventListener('product:variant-change', (e) => {
      console.log('🔄 Product variant-change event detected:', e.detail);
      this.updateButtonStates();
    });
  }

  async initializeButtons() {
    console.log('🔍 Looking for wishlist buttons...');
    console.log('🔍 DOM ready state:', document.readyState);
    console.log('🔍 Total elements in DOM:', document.querySelectorAll('*').length);
    
    // Look for both the specific class and the generic wishlist button
    const specificButtons = document.querySelectorAll('.metallbude-wishlist-btn');
    const genericButtons = document.querySelectorAll('.wishlist-btn');
    const allWishlistButtons = [...specificButtons, ...genericButtons];
    
    console.log(`🔧 Found ${specificButtons.length} specific wishlist buttons`);
    console.log(`🔧 Found ${genericButtons.length} generic wishlist buttons`);
    console.log(`🔧 Total wishlist buttons: ${allWishlistButtons.length}`);
    
    if (allWishlistButtons.length === 0) {
      console.warn('⚠️ No wishlist buttons found! Looking for all buttons...');
      const allButtons = document.querySelectorAll('button');
      console.log(`🔍 Total buttons in DOM: ${allButtons.length}`);
      allButtons.forEach((btn, index) => {
        if (index < 10) { // Only log first 10 to avoid spam
          console.log(`  Button ${index}: class="${btn.className}", id="${btn.id}"`);
        }
      });
    }
    
    // Initialize all found wishlist buttons
    for (const button of allWishlistButtons) {
      // Add our specific class if it doesn't have it
      if (!button.classList.contains('metallbude-wishlist-btn')) {
        button.classList.add('metallbude-wishlist-btn');
      }
      
      const productId = this.getProductId(button);
      console.log('🔧 Initializing button for product:', productId);
      await this.updateButtonState(button);
    }
  }

  async handleWishlistClick(button) {
    if (button.disabled) return;

    // Disable button during operation
    button.disabled = true;
    const originalContent = button.innerHTML;
    button.innerHTML = '<span class="spinner">⏳</span>';

    try {
      const productId = this.getProductId(button);
      const variantId = this.getCurrentVariantId(button);
      const selectedOptions = this.getSelectedOptions(button);
      const productData = this.getProductData(button);

      const isInWishlist = button.classList.contains('in-wishlist');
      console.log(`🔄 Handling wishlist click: ${isInWishlist ? 'REMOVING' : 'ADDING'} variant ${variantId}`);

      if (isInWishlist) {
        await this.removeFromWishlist(productId, variantId, selectedOptions);
        console.log('✅ Successfully removed from wishlist');
        // ✅ FIXED: Immediately set to NOT in wishlist after successful removal
        this.setButtonState(button, false);
      } else {
        await this.addToWishlist(productId, variantId, selectedOptions, productData);
        console.log('✅ Successfully added to wishlist');
        // ✅ FIXED: Immediately set to IN wishlist after successful addition
        this.setButtonState(button, true);
      }

      // ✅ ENHANCED: Double-check state after a short delay to ensure consistency
      setTimeout(async () => {
        console.log('🔄 Double-checking button state after operation with fresh data...');
        await this.updateButtonState(button, true); // Use cache-busting
      }, 500);

      this.showFeedback(isInWishlist ? 'removed' : 'added');

    } catch (error) {
      console.error('Error handling wishlist click:', error);
      this.showError('Fehler beim Bearbeiten der Wunschliste');
      
      // ✅ FIXED: Revert button state on error
      await this.updateButtonState(button);
    } finally {
      button.disabled = false;
      if (button.innerHTML.includes('spinner')) {
        button.innerHTML = originalContent;
      }
    }
  }

  getProductId(button) {
    return button.getAttribute('data-product-id') || 
           button.closest('[data-product-id]')?.getAttribute('data-product-id');
  }

  getCurrentVariantId(button) {
    // Try to get from button data first
    let variantId = button.getAttribute('data-variant-id');
    if (variantId) {
      console.log('🔍 Found variant ID from button data:', variantId);
      return variantId;
    }

    // Try to get from variant selector in the same form/section as the button
    const productForm = button.closest('form[action*="/cart/add"]') || 
                       button.closest('.product-form') ||
                       button.closest('[data-product-id]') ||
                       document.querySelector('form[action*="/cart/add"]');
    
    if (productForm) {
      const variantSelector = productForm.querySelector('select[name="id"], input[name="id"]:checked, .variant-selector:checked');
      if (variantSelector && variantSelector.value) {
        console.log('🔍 Found variant ID from form selector:', variantSelector.value);
        return variantSelector.value;
      }
    }

    // Try to get from global variant selectors
    const globalVariantSelector = document.querySelector('select[name="id"], input[name="id"]:checked');
    if (globalVariantSelector && globalVariantSelector.value) {
      console.log('🔍 Found variant ID from global selector:', globalVariantSelector.value);
      return globalVariantSelector.value;
    }

    // Try to get from Shopify variant change events
    if (window.currentVariant && window.currentVariant.id) {
      console.log('🔍 Found variant ID from window.currentVariant:', window.currentVariant.id);
      return window.currentVariant.id.toString();
    }

    // Try to get from URL parameters (for direct variant links)
    const urlParams = new URLSearchParams(window.location.search);
    const variantParam = urlParams.get('variant');
    if (variantParam) {
      console.log('🔍 Found variant ID from URL parameter:', variantParam);
      return variantParam;
    }

    console.log('🔍 No variant ID found');
    return null;
  }

  getSelectedOptions(button) {
    const options = {};
    
    // Get product form if available
    const productForm = button.closest('form[action*="/cart/add"]') || 
                       button.closest('.product-form') ||
                       button.closest('[data-product-id]') ||
                       document.querySelector('form[action*="/cart/add"]');
    
    if (productForm) {
      console.log('🔍 Found product form, extracting options...');
      
      // Get all option selectors - support multiple formats
      const optionSelectors = productForm.querySelectorAll(`
        [name^="properties["], 
        select[data-option], 
        input[data-option]:checked,
        select[data-option-name],
        input[data-option-name]:checked,
        .option-selector,
        .variant-input:checked,
        select[name*="option"],
        input[name*="option"]:checked
      `);
      
      console.log(`🔍 Found ${optionSelectors.length} option selectors`);
      
      optionSelectors.forEach((selector, index) => {
        console.log(`🔍 Processing option selector ${index}:`, {
          name: selector.name,
          value: selector.value,
          dataOption: selector.getAttribute('data-option'),
          dataOptionName: selector.getAttribute('data-option-name')
        });
        
        let optionName = selector.getAttribute('data-option') || 
                        selector.getAttribute('data-option-name') ||
                        selector.name.replace(/properties\[|\]|option/g, '').trim();
        
        if (optionName && selector.value && selector.value !== '') {
          options[optionName] = selector.value;
          console.log(`🔍 Added option: ${optionName} = ${selector.value}`);
        }
      });

      // Also check for Shopify's standard option selectors
      const shopifyOptions = productForm.querySelectorAll('.product-form__input');
      shopifyOptions.forEach((input) => {
        if (input.type === 'radio' && input.checked) {
          const label = productForm.querySelector(`label[for="${input.id}"]`);
          if (label) {
            const optionName = label.getAttribute('data-option-name') || 'Option';
            options[optionName] = input.value;
            console.log(`🔍 Added Shopify option: ${optionName} = ${input.value}`);
          }
        } else if (input.tagName === 'SELECT') {
          const optionName = input.getAttribute('data-option-name') || input.name || 'Option';
          if (input.value) {
            options[optionName] = input.value;
            console.log(`🔍 Added Shopify select option: ${optionName} = ${input.value}`);
          }
        }
      });
    }

    console.log('🔍 Final selected options:', options);
    return options;
  }

  getProductData(button) {
    const productData = {
      title: button.getAttribute('data-product-title') || document.title,
      handle: button.getAttribute('data-product-handle') || window.location.pathname.split('/').pop(),
      price: 0,
      imageUrl: '',
      sku: ''
    };

    // Try to get current variant data
    const variantId = this.getCurrentVariantId(button);
    if (variantId && window.productVariants) {
      const variant = window.productVariants.find(v => v.id.toString() === variantId);
      if (variant) {
        productData.price = variant.price;
        productData.sku = variant.sku || '';
        productData.imageUrl = variant.featured_image?.url || '';
      }
    }

    // Fallback to product-level data
    if (!productData.imageUrl) {
      const featuredImage = document.querySelector('.product-image img, .featured-image img');
      if (featuredImage) {
        productData.imageUrl = featuredImage.src;
      }
    }

    return productData;
  }

  async addToWishlist(productId, variantId, selectedOptions, productData) {
    console.log('➕ Adding to wishlist:', { productId, variantId, selectedOptions });

    // Ensure proper GID format for productId
    const formattedProductId = productId.includes('gid://') ? productId : `gid://shopify/Product/${productId}`;
    
    // Format variantId properly - only add GID if it's not already in GID format and it's not null
    let formattedVariantId = variantId;
    if (variantId && !variantId.includes('gid://')) {
      formattedVariantId = `gid://shopify/ProductVariant/${variantId}`;
    }

    const response = await fetch(`${this.backendUrl}/api/public/wishlist/add`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        customerId: this.customerId,
        productId: formattedProductId,
        variantId: formattedVariantId,
        selectedOptions: selectedOptions,
        title: productData.title,
        imageUrl: productData.imageUrl,
        price: productData.price,
        sku: productData.sku,
        handle: productData.handle
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to add to wishlist: ${response.status}`);
    }

    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || 'Failed to add to wishlist');
    }

    return data;
  }

  async removeFromWishlist(productId, variantId, selectedOptions) {
    console.log('➖ Removing from wishlist:', { productId, variantId, selectedOptions });

    // Ensure proper GID format for productId
    const formattedProductId = productId.includes('gid://') ? productId : `gid://shopify/Product/${productId}`;
    
    // Format variantId properly - only add GID if it's not already in GID format and it's not null
    let formattedVariantId = variantId;
    if (variantId && !variantId.includes('gid://')) {
      formattedVariantId = `gid://shopify/ProductVariant/${variantId}`;
    }

    const response = await fetch(`${this.backendUrl}/api/public/wishlist/remove`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        customerId: this.customerId,
        productId: formattedProductId,
        variantId: formattedVariantId,
        selectedOptions: selectedOptions
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to remove from wishlist: ${response.status}`);
    }

    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || 'Failed to remove from wishlist');
    }

    return data;
  }

  async checkWishlistStatus(productId, variantId, selectedOptions, bustCache = false) {
    try {
      console.log('🔍 Checking wishlist status for:', { productId, variantId, selectedOptions, bustCache });
      
      // ✅ ENHANCED: Add cache-busting parameter for fresh data after operations
      const url = new URL(`${this.backendUrl}/api/public/wishlist/items`);
      url.searchParams.set('customerId', this.customerId);
      if (bustCache) {
        url.searchParams.set('_t', Date.now().toString());
      }
      
      const response = await fetch(url.toString());
      
      if (!response.ok) {
        console.error('Failed to fetch wishlist:', response.status);
        return false;
      }

      const data = await response.json();
      if (!data.success || !data.items) {
        console.error('Invalid wishlist response:', data);
        return false;
      }

      console.log('📥 Wishlist items:', data.items.length);

      // ✅ FIXED: Proper variant-specific matching
      const isInWishlist = data.items.some(item => {
        const itemProductId = this.normalizeId(item.productId);
        const currentProductId = this.normalizeId(productId);
        
        console.log('🔍 Comparing products:', { itemProductId, currentProductId });
        
        // Must match product first
        if (itemProductId !== currentProductId) return false;

        // ✅ CRITICAL: If we have a variant ID, it MUST match exactly
        if (variantId) {
          const itemVariantId = this.normalizeId(item.variantId);
          const currentVariantId = this.normalizeId(variantId);
          
          console.log('🔍 Comparing variants (STRICT):', { 
            itemVariantId, 
            currentVariantId,
            itemSKU: item.sku,
            match: itemVariantId === currentVariantId 
          });
          
          // For variant-specific checking, variant IDs must match exactly
          if (itemVariantId && currentVariantId) {
            return itemVariantId === currentVariantId;
          }
          
          // If current variant exists but item has no variant, it's not a match
          if (currentVariantId && !itemVariantId) {
            console.log('🔍 Current variant exists but item has no variant - NO MATCH');
            return false;
          }
        }

        // ✅ ENHANCED: Match by selected options if available (for variant-level granularity)
        if (selectedOptions && Object.keys(selectedOptions).length > 0) {
          if (!item.selectedOptions || Object.keys(item.selectedOptions).length === 0) {
            console.log('🔍 Current has options but item has no options - NO MATCH');
            return false;
          }
          
          // Check if all current options match item options
          for (const [key, value] of Object.entries(selectedOptions)) {
            if (item.selectedOptions[key] !== value) {
              console.log(`🔍 Option mismatch: ${key} = "${value}" vs "${item.selectedOptions[key]}" - NO MATCH`);
              return false;
            }
          }
          
          console.log('🔍 All options match - MATCH');
          return true;
        }

        // ✅ STRICT: If no variant or options specified but item has them, it's not a generic match
        if ((!variantId && !selectedOptions) && (item.variantId || (item.selectedOptions && Object.keys(item.selectedOptions).length > 0))) {
          console.log('🔍 Generic product check but item has specific variant/options - NO MATCH');
          return false;
        }

        // Only match if both are product-level (no variants)
        console.log('🔍 Both are product-level items - MATCH');
        return true;
      });

      console.log('✅ Wishlist check result (variant-specific):', isInWishlist);
      return isInWishlist;

    } catch (error) {
      console.error('Error checking wishlist status:', error);
      return false;
    }
  }

  extractProductId(shopifyGid) {
    if (typeof shopifyGid === 'string' && shopifyGid.includes('gid://shopify/Product/')) {
      return shopifyGid.split('/').pop();
    }
    return shopifyGid;
  }

  extractVariantId(shopifyGid) {
    if (typeof shopifyGid === 'string' && shopifyGid.includes('gid://shopify/ProductVariant/')) {
      return shopifyGid.split('/').pop();
    }
    return shopifyGid;
  }

  normalizeId(id) {
    if (!id) return null;
    // Convert to string and extract numeric part if it's a GID
    const idStr = String(id);
    if (idStr.includes('gid://shopify/')) {
      return idStr.split('/').pop();
    }
    return idStr;
  }

  async updateButtonState(button, bustCache = false) {
    const productId = this.getProductId(button);
    const variantId = this.getCurrentVariantId(button);
    const selectedOptions = this.getSelectedOptions(button);

    console.log('🔄 Updating button state for:', { 
      productId, 
      variantId, 
      selectedOptions,
      optionKeys: Object.keys(selectedOptions),
      hasVariant: !!variantId,
      bustCache
    });

    if (!productId) {
      console.warn('⚠️ No product ID found for button');
      return;
    }

    try {
      const isInWishlist = await this.checkWishlistStatus(productId, variantId, selectedOptions, bustCache);
      console.log(`🔄 Button state result: ${isInWishlist ? 'IN WISHLIST' : 'NOT IN WISHLIST'}`);
      this.setButtonState(button, isInWishlist);
    } catch (error) {
      console.error('❌ Error updating button state:', error);
      // Set button to default state on error
      this.setButtonState(button, false);
    }
  }

  async updateButtonStates() {
    // Update both specific and generic wishlist buttons
    const specificButtons = document.querySelectorAll('.metallbude-wishlist-btn');
    const genericButtons = document.querySelectorAll('.wishlist-btn');
    const allButtons = [...specificButtons, ...genericButtons];
    
    for (const button of allButtons) {
      await this.updateButtonState(button);
    }
  }

  setButtonState(button, isInWishlist) {
    console.log(`🎨 Setting button state: ${isInWishlist ? 'IN WISHLIST' : 'NOT IN WISHLIST'}`);
    
    // ✅ FIXED: Force remove/add classes to ensure clean state
    button.classList.remove('in-wishlist', 'not-in-wishlist');
    
    if (isInWishlist) {
      button.classList.add('in-wishlist');
      button.setAttribute('aria-label', 'Von Wunschliste entfernen');
      
      // Update button content
      const icon = button.querySelector('.wishlist-icon');
      const text = button.querySelector('.wishlist-text');
      
      if (icon) icon.innerHTML = '❤️'; // Filled heart
      if (text) text.textContent = 'In Wunschliste';
      
      // ✅ ENHANCED: More aggressive button content replacement
      if (!icon && !text) {
        let content = button.innerHTML;
        if (content.includes('🤍') || content.includes('♡') || content.includes('🖤')) {
          content = content.replace(/🤍|♡|🖤/g, '❤️');
          button.innerHTML = content;
        } else if (content.includes('Zur Wunschliste')) {
          content = content.replace('Zur Wunschliste', 'In Wunschliste');
          button.innerHTML = content;
        }
      }
      
    } else {
      button.classList.add('not-in-wishlist');
      button.setAttribute('aria-label', 'Zur Wunschliste hinzufügen');
      
      // Update button content
      const icon = button.querySelector('.wishlist-icon');
      const text = button.querySelector('.wishlist-text');
      
      if (icon) icon.innerHTML = '🤍'; // Empty heart
      if (text) text.textContent = 'Zur Wunschliste';
      
      // ✅ ENHANCED: More aggressive button content replacement
      if (!icon && !text) {
        let content = button.innerHTML;
        if (content.includes('❤️') || content.includes('♥') || content.includes('🖤')) {
          content = content.replace(/❤️|♥|🖤/g, '🤍');
          button.innerHTML = content;
        } else if (content.includes('In Wunschliste')) {
          content = content.replace('In Wunschliste', 'Zur Wunschliste');
          button.innerHTML = content;
        }
      }
    }
    
    // Add variant info for debugging
    const variantId = this.getCurrentVariantId(button);
    const selectedOptions = this.getSelectedOptions(button);
    if (variantId || Object.keys(selectedOptions).length > 0) {
      button.setAttribute('data-current-variant', variantId || 'options');
      button.setAttribute('data-current-options', JSON.stringify(selectedOptions));
    }
    
    // ✅ DEBUGGING: Log the final button state
    console.log('🎨 Final button classes:', button.className);
    console.log('🎨 Final button content:', button.innerHTML.substring(0, 50) + '...');
  }

  showFeedback(action) {
    const message = action === 'added' ? 
      'Zur Wunschliste hinzugefügt!' : 
      'Von Wunschliste entfernt!';

    // Create feedback element
    const feedback = document.createElement('div');
    feedback.className = 'metallbude-wishlist-feedback';
    feedback.textContent = message;
    feedback.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #000;
      color: white;
      padding: 12px 24px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 500;
      z-index: 10000;
      opacity: 0;
      transform: translateX(100%);
      transition: all 0.3s ease;
    `;

    document.body.appendChild(feedback);

    // Animate in
    requestAnimationFrame(() => {
      feedback.style.opacity = '1';
      feedback.style.transform = 'translateX(0)';
    });

    // Remove after delay
    setTimeout(() => {
      feedback.style.opacity = '0';
      feedback.style.transform = 'translateX(100%)';
      setTimeout(() => feedback.remove(), 300);
    }, 2000);
  }

  showError(message) {
    console.error('Wishlist error:', message);
    
    // Create error feedback
    const feedback = document.createElement('div');
    feedback.className = 'metallbude-wishlist-error';
    feedback.textContent = message;
    feedback.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #dc3545;
      color: white;
      padding: 12px 24px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 500;
      z-index: 10000;
      opacity: 0;
      transform: translateX(100%);
      transition: all 0.3s ease;
    `;

    document.body.appendChild(feedback);

    // Animate in
    requestAnimationFrame(() => {
      feedback.style.opacity = '1';
      feedback.style.transform = 'translateX(0)';
    });

    // Remove after delay
    setTimeout(() => {
      feedback.style.opacity = '0';
      feedback.style.transform = 'translateX(100%)';
      setTimeout(() => feedback.remove(), 300);
    }, 3000);
  }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.metallbudeWishlist = new MetallbudeWishlistButton();
  });
} else {
  window.metallbudeWishlist = new MetallbudeWishlistButton();
}

// CSS Styles for wishlist button
const wishlistStyles = `
.metallbude-wishlist-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: transparent;
  border: 1px solid #000;
  border-radius: 20px;
  padding: 8px 16px;
  font-size: 14px;
  font-weight: 500;
  color: #000;
  cursor: pointer;
  transition: all 0.2s ease;
  text-decoration: none;
  min-height: 40px;
}

.metallbude-wishlist-btn:hover {
  background: transparent !important;
  color: #000 !important;
  border-color: #000 !important;
}

.metallbude-wishlist-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.wishlist-icon {
  font-size: 16px;
  line-height: 1;
}

.wishlist-text {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.spinner {
  animation: spin 1s linear infinite;
  display: inline-block;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.metallbude-wishlist-feedback,
.metallbude-wishlist-error {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
`;

// Inject styles
if (!document.querySelector('#metallbude-wishlist-styles')) {
  const styleSheet = document.createElement('style');
  styleSheet.id = 'metallbude-wishlist-styles';
  styleSheet.textContent = wishlistStyles;
  document.head.appendChild(styleSheet);
}
