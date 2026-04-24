const express = require('express');
const axios = require('axios');

const router = express.Router();

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const ADMIN_API_VERSION = process.env.SHOPIFY_ADMIN_API_VERSION || '2024-10';

// Per-instance cache (5 min). Discounts change rarely.
const CACHE_TTL_MS = 5 * 60 * 1000;
let cache = { fetchedAt: 0, discounts: null };

function getAdminGraphqlEndpoint() {
  const store = String(SHOPIFY_STORE || '').trim();
  if (!store) return null;
  return `https://${store}/admin/api/${ADMIN_API_VERSION}/graphql.json`;
}

async function fetchAllAutomaticDiscounts() {
  if (cache.discounts && Date.now() - cache.fetchedAt < CACHE_TTL_MS) {
    return cache.discounts;
  }

  const endpoint = getAdminGraphqlEndpoint();
  if (!endpoint) {
    throw new Error('Shopify store not configured (set SHOPIFY_STORE or SHOPIFY_SHOP_DOMAIN)');
  }

  const query = `
    query AutomaticDiscounts($cursor: String) {
      automaticDiscountNodes(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        edges {
          node {
            id
            automaticDiscount {
              __typename
              ... on DiscountAutomaticBasic {
                title
                status
                startsAt
                endsAt
                summary
                minimumRequirement {
                  __typename
                  ... on DiscountMinimumQuantity { greaterThanOrEqualToQuantity }
                }
                customerGets {
                  value {
                    __typename
                    ... on DiscountPercentage { percentage }
                    ... on DiscountAmount { amount { amount currencyCode } }
                  }
                  items {
                    __typename
                    ... on AllDiscountItems { allItems }
                    ... on DiscountProducts {
                      products(first: 50) { edges { node { id } } }
                      productVariants(first: 50) { edges { node { id product { id } } } }
                    }
                    ... on DiscountCollections {
                      collections(first: 25) {
                        edges {
                          node {
                            id
                            products(first: 100) { edges { node { id } } }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  `;

  const all = [];
  let cursor = null;

  while (true) {
    const response = await axios.post(
      endpoint,
      { query, variables: { cursor } },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
        },
        timeout: 20000,
      }
    );

    const body = response.data || {};
    if (body.errors) {
      throw new Error(`GraphQL: ${JSON.stringify(body.errors)}`);
    }

    const data = body.data?.automaticDiscountNodes;
    if (!data) break;

    for (const edge of data.edges || []) {
      all.push(edge.node);
    }

    if (!data.pageInfo?.hasNextPage) break;
    cursor = data.pageInfo.endCursor;
  }

  cache = { fetchedAt: Date.now(), discounts: all };
  return all;
}

function discountAppliesToProduct(node, productId) {
  const auto = node?.automaticDiscount;
  if (!auto || (auto.status && auto.status !== 'ACTIVE')) return false;

  const items = auto.customerGets?.items;
  if (!items) return false;

  switch (items.__typename) {
    case 'AllDiscountItems':
      return Boolean(items.allItems);
    case 'DiscountProducts': {
      if ((items.products?.edges || []).some((e) => e.node?.id === productId)) return true;
      return (items.productVariants?.edges || []).some((e) => e.node?.product?.id === productId);
    }
    case 'DiscountCollections':
      return (items.collections?.edges || []).some((c) =>
        (c.node?.products?.edges || []).some((p) => p.node?.id === productId)
      );
    default:
      return false;
  }
}

function nodeToTier(node) {
  const auto = node?.automaticDiscount;
  if (!auto) return null;

  const min = auto.minimumRequirement;
  if (!min || min.__typename !== 'DiscountMinimumQuantity') return null;

  const quantity = Number(min.greaterThanOrEqualToQuantity);
  if (!quantity || quantity < 1) return null;

  let discountPercent = 0;
  const value = auto.customerGets?.value;
  if (value?.__typename === 'DiscountPercentage') {
    // Shopify returns 0..1, transform to 0..100.
    discountPercent = Number(value.percentage) * 100;
  }

  return {
    quantity,
    label: `${quantity}ER SET`,
    discountPercent: Math.round(discountPercent * 100) / 100,
    discountCode: (auto.title || '').trim() || null,
    popular: false,
  };
}

router.get('/api/public/bundle-offers', async (req, res) => {
  try {
    const productId = String(req.query.productId || '').trim();
    if (!productId) {
      return res.status(400).json({ error: 'productId required' });
    }

    if (!SHOPIFY_STORE || !SHOPIFY_ADMIN_TOKEN) {
      return res.status(500).json({ error: 'Shopify Admin not configured' });
    }

    const discounts = await fetchAllAutomaticDiscounts();
    const tiers = discounts
      .filter((node) => discountAppliesToProduct(node, productId))
      .map(nodeToTier)
      .filter(Boolean)
      .sort((a, b) => a.quantity - b.quantity);

    if (tiers.length >= 3) tiers[Math.floor(tiers.length / 2)].popular = true;
    else if (tiers.length === 2) tiers[1].popular = true;

    console.log(`[bundle-offers] productId=${productId} tiers=${tiers.length}`);
    return res.json({ offers: tiers });
  } catch (error) {
    console.error('[bundle-offers] error:', error.response?.data || error.message || error);
    return res.status(500).json({ error: error.message || 'Failed to load bundle offers' });
  }
});

module.exports = router;
