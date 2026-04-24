const express = require('express');
const axios = require('axios');

const router = express.Router();

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const ADMIN_API_VERSION = process.env.SHOPIFY_ADMIN_API_VERSION || '2024-10';

// 5-minute per-handle cache
const SCRAPE_TTL_MS = 5 * 60 * 1000;
const scrapeCache = new Map(); // handle -> { fetchedAt, offers }

const STOREFRONT_BASE =
  process.env.STOREFRONT_BASE_URL || 'https://metallbude.com';

async function fetchProductHandleById(productId) {
  const endpoint = `https://${SHOPIFY_STORE}/admin/api/${ADMIN_API_VERSION}/graphql.json`;
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
    },
    body: JSON.stringify({
      query: `query($id: ID!) { product(id: $id) { handle } }`,
      variables: { id: productId },
    }),
  }).then((resp) => resp.json());
  return r?.data?.product?.handle || null;
}

function parseBundleConfig(html) {
  // Sectionheroes injects: <script type="application/json" data-bundle-config>{...}</script>
  const re = /<script[^>]*data-bundle-config[^>]*>([\s\S]*?)<\/script>/gi;
  const configs = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      configs.push(JSON.parse(String(m[1] || '').trim()));
    } catch (e) {
      console.warn('[bundle-offers] failed to parse a data-bundle-config block:', e.message);
    }
  }
  return configs;
}

function mapSectionheroesToTiers(config) {
  const offers = Array.isArray(config?.offers) ? config.offers : [];
  const bundleId = config?.shortId || config?.id || null;
  const tiers = [];
  offers.forEach((o, index) => {
    const quantity = Number(o.quantity);
    if (!quantity || quantity < 1) return;
    const d = o.discount || {};
    const discountPercent = d.type === 'percentage' ? (Number(d.value) || 0) : 0;
    tiers.push({
      quantity,
      label: o.content?.title || `${quantity}× SET`,
      badge: o.content?.badge || null,
      discountPercent: Math.round(discountPercent * 100) / 100,
      discountCode: null,
      popular: !!o.preselect,
      preselect: Boolean(o.preselect),
      bundleId, // e.g. "gal5q"
      offerIndex: index, // 0-based: matches Sectionheroes "o"
    });
  });
  tiers.sort((a, b) => a.quantity - b.quantity);
  return tiers;
}

async function scrapeBundleConfig(handle) {
  const normalizedHandle = String(handle || '').trim();
  if (!normalizedHandle) throw new Error('handle required');

  const cached = scrapeCache.get(normalizedHandle);
  if (cached && Date.now() - cached.fetchedAt < SCRAPE_TTL_MS) {
    return cached.value;
  }

  const url = `${STOREFRONT_BASE}/products/${normalizedHandle}`;
  const response = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Metallbude-App-Backend) Bundle-Resolver/1.0',
      Accept: 'text/html',
    },
  });
  if (!response.ok) throw new Error(`storefront ${response.status}`);
  const html = await response.text();

  const matches = [];
  let m;

  // Strategy 1: script tags whose id/data contains sh-bundle
  const scriptRe = /<script[^>]*(?:id|data-[a-z-]+)=["'][^"']*sh[-_]?bundle[^"']*["'][^>]*>([\s\S]*?)<\/script>/gi;
  while ((m = scriptRe.exec(html)) !== null) matches.push(String(m[1] || '').trim());

  // Strategy 2: window.__SH_BUNDLE__ style globals
  const winRe = /window\.__SH[_A-Z]*BUNDLE[_A-Z]*\s*=\s*(\{[\s\S]*?\});/g;
  while ((m = winRe.exec(html)) !== null) matches.push(String(m[1] || '').trim());

  // Strategy 3: broad json-like fragments with likely tier/quantity keys
  const broadRe = /\{[^{}]*?"id"\s*:\s*"[a-z0-9]{4,8}"[^{}]*?(?:"tiers"|"quantity"|"discount")[\s\S]{0,2000}?\}/gi;
  while ((m = broadRe.exec(html)) !== null) matches.push(String(m[0] || '').trim());

  const result = {
    url,
    htmlLength: html.length,
    candidates: matches.slice(0, 5),
  };
  scrapeCache.set(normalizedHandle, { fetchedAt: Date.now(), value: result });
  return result;
}

router.get('/api/public/bundle-offers', async (req, res) => {
  try {
    const productId = String(req.query.productId || '');
    let handle = String(req.query.handle || '');
    if (!productId && !handle) {
      return res.status(400).json({ error: 'productId or handle required' });
    }

    if (!handle) {
      handle = await fetchProductHandleById(productId);
      if (!handle) return res.json({ offers: [] });
    }

    const cached = scrapeCache.get(handle);
    if (cached && Date.now() - cached.fetchedAt < SCRAPE_TTL_MS) {
      return res.json({ offers: cached.offers, cached: true });
    }

    const url = `${STOREFRONT_BASE}/products/${handle}`;
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 Metallbude-App-Backend/1.0',
        Accept: 'text/html',
      },
    });
    if (!response.ok) {
      console.warn(`[bundle-offers] storefront ${response.status} for ${url}`);
      return res.json({ offers: [] });
    }

    const html = await response.text();
    const configs = parseBundleConfig(html);
    if (configs.length === 0) {
      console.log(`[bundle-offers] no bundle-config block for ${handle}`);
      scrapeCache.set(handle, { fetchedAt: Date.now(), offers: [] });
      return res.json({ offers: [] });
    }

    // A product page may render multiple bundle blocks; merge them.
    const offers = configs.flatMap(mapSectionheroesToTiers);
    // De-dupe by quantity (keep first / highest-discount).
    const byQty = new Map();
    for (const t of offers) {
      const existing = byQty.get(t.quantity);
      if (!existing || t.discountPercent > existing.discountPercent) {
        byQty.set(t.quantity, t);
      }
    }
    const merged = [...byQty.values()].sort((a, b) => a.quantity - b.quantity);

    scrapeCache.set(handle, { fetchedAt: Date.now(), offers: merged });
    console.log(
      `[bundle-offers] handle=${handle} tiers=${merged.length} (${merged.map((t) => `${t.quantity}x@-${t.discountPercent}%`).join(',')})`
    );
    return res.json({ offers: merged });
  } catch (error) {
    console.error('[bundle-offers] error:', error);
    return res.status(500).json({ error: error.message });
  }
});

router.get('/api/public/bundle-offers/scrape-debug', async (req, res) => {
  try {
    const handle = String(req.query.handle || 'leather-s-hooks-3-piece-set');
    return res.json(await scrapeBundleConfig(handle));
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

router.get('/api/public/bundle-offers/debug-apps', async (req, res) => {
  try {
    const endpoint = `https://${SHOPIFY_STORE}/admin/api/${ADMIN_API_VERSION}/graphql.json`;
    const apps = [];
    let cursor = null;

    while (true) {
      const r = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
        },
        body: JSON.stringify({
          query: `
            query($cursor: String) {
              appInstallations(first: 100, after: $cursor) {
                pageInfo { hasNextPage endCursor }
                edges { node { id app { title handle appStoreAppUrl } } }
              }
            }`,
          variables: { cursor },
        }),
      }).then((resp) => resp.json());

      const data = r?.data?.appInstallations;
      if (!data) break;
      for (const edge of data.edges || []) apps.push(edge.node);
      if (!data.pageInfo.hasNextPage) break;
      cursor = data.pageInfo.endCursor;
    }

    return res.json({ count: apps.length, apps: apps.map((a) => a.app) });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

router.get('/api/public/bundle-offers/debug', async (req, res) => {
  try {
    const productId = String(req.query.productId || 'gid://shopify/Product/6698295525540');
    const endpoint = `https://${SHOPIFY_STORE}/admin/api/${ADMIN_API_VERSION}/graphql.json`;

    const gql = async (query, variables) => {
      const response = await axios.post(
        endpoint,
        { query, variables },
        {
          headers: {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
          },
          timeout: 30000,
        }
      );
      return response.data;
    };

    const shopMeta = await gql(`
      {
        shop {
          metafields(first: 250) {
            edges { node { namespace key type value } }
          }
        }
      }
    `);

    const appsMeta = await gql(`
      {
        currentAppInstallation { id }
        appInstallations(first: 50) {
          edges {
            node {
              id
              app { id title appStoreAppUrl handle }
              metafields(first: 50) {
                edges { node { namespace key type value } }
              }
            }
          }
        }
      }
    `);

    const defs = await gql(`
      {
        metafieldDefinitions(first: 250, ownerType: PRODUCT) {
          edges { node { namespace key name type { name } } }
        }
      }
    `);

    const allDiscounts = [];
    let cursor = null;

    while (true) {
      const page = await gql(`
        query Page($cursor: String) {
          automaticDiscountNodes(first: 100, after: $cursor) {
            pageInfo { hasNextPage endCursor }
            edges {
              node {
                id
                automaticDiscount {
                  __typename
                  ... on DiscountAutomaticApp {
                    title
                    status
                    appDiscountType { appKey functionId title description }
                  }
                  ... on DiscountAutomaticBxgy { title status summary }
                  ... on DiscountAutomaticBasic { title status }
                  ... on DiscountAutomaticFreeShipping { title status }
                }
              }
            }
          }
        }
      `, { cursor });

      const data = page?.data?.automaticDiscountNodes;
      if (!data) break;
      for (const edge of data.edges || []) allDiscounts.push(edge.node);
      if (!data.pageInfo?.hasNextPage) break;
      cursor = data.pageInfo.endCursor;
    }

    const matchSH = (s) =>
      typeof s === 'string' && /section.?heroes|sh.?bundle|^sh[_-]/i.test(s);

    const shopHits = (shopMeta?.data?.shop?.metafields?.edges || []).filter((e) => {
      const node = e?.node || {};
      return (
        matchSH(node.namespace) ||
        matchSH(node.key) ||
        String(node.value || '').includes('gal5q') ||
        String(node.value || '').includes('ikloj')
      );
    });

    const appHits = (appsMeta?.data?.appInstallations?.edges || []).map((e) => ({
      app: e.node.app,
      metafields: (e.node.metafields?.edges || []).map((m) => m.node),
    }));

    const defHits = (defs?.data?.metafieldDefinitions?.edges || []).filter((e) => {
      const node = e?.node || {};
      return matchSH(node.namespace) || matchSH(node.key);
    });

    const discountHits = allDiscounts.filter(
      (n) => n?.automaticDiscount?.__typename === 'DiscountAutomaticApp'
    );

    return res.json({
      productId,
      counts: {
        shopMetafields: shopMeta?.data?.shop?.metafields?.edges?.length || 0,
        installedApps: appsMeta?.data?.appInstallations?.edges?.length || 0,
        productMetafieldDefinitions: defs?.data?.metafieldDefinitions?.edges?.length || 0,
        automaticDiscountsTotal: allDiscounts.length,
        appBasedDiscounts: discountHits.length,
      },
      sectionheroesShopMetafieldHits: shopHits.map((e) => e.node),
      sectionheroesProductMetafieldDefinitionHits: defHits.map((e) => e.node),
      appBasedDiscounts: discountHits,
      installedAppsWithMetafields: appHits,
      _raw: { shopMeta, defs },
    });
  } catch (e) {
    return res.status(500).json({ error: e.message, stack: e.stack });
  }
});

router.get('/api/public/bundle-offers/debug-sh', async (req, res) => {
  try {
    const endpoint = `https://${SHOPIFY_STORE}/admin/api/${ADMIN_API_VERSION}/graphql.json`;
    const gql = (query, variables) =>
      fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
        },
        body: JSON.stringify({ query, variables }),
      }).then((r) => r.json());

    let installId = null;
    let appId = null;
    let cursor = null;
    while (true) {
      const r = await gql(`
        query($c: String) {
          appInstallations(first: 100, after: $c) {
            pageInfo { hasNextPage endCursor }
            edges { node { id app { id title handle } } }
          }
        }`, { c: cursor });
      const data = r?.data?.appInstallations;
      if (!data) break;
      const hit = (data.edges || []).find((e) =>
        /sectionheroes/i.test(e?.node?.app?.handle || e?.node?.app?.title || '')
      );
      if (hit) {
        installId = hit.node.id;
        appId = hit.node.app.id;
        break;
      }
      if (!data.pageInfo.hasNextPage) break;
      cursor = data.pageInfo.endCursor;
    }

    if (!installId) return res.json({ error: 'sectionheroes not found' });

    const allMeta = [];
    cursor = null;
    while (true) {
      const r = await gql(`
        query($id: ID!, $c: String) {
          appInstallation(id: $id) {
            metafields(first: 250, after: $c) {
              pageInfo { hasNextPage endCursor }
              edges { node { namespace key type value } }
            }
          }
        }`, { id: installId, c: cursor });
      const data = r?.data?.appInstallation?.metafields;
      if (!data) break;
      for (const e of data.edges || []) allMeta.push(e.node);
      if (!data.pageInfo.hasNextPage) break;
      cursor = data.pageInfo.endCursor;
    }

    const productId = String(req.query.productId || 'gid://shopify/Product/6698295525540');
    const productMeta = await gql(`
      query($id: ID!) {
        product(id: $id) {
          handle
          metafields(first: 250) {
            edges { node { namespace key type value } }
          }
        }
      }`, { id: productId });

    const productAll = (productMeta?.data?.product?.metafields?.edges || []).map((e) => e.node);
    const productAppOwned = productAll.filter((m) =>
      /^\$app|sectionheroes|^sh[_-]|bundle/i.test(m.namespace) ||
      String(m.value || '').includes('gal5q') ||
      String(m.value || '').includes('ikloj')
    );

    return res.json({
      productId,
      sectionheroes: { installId, appId },
      installationMetafieldCount: allMeta.length,
      installationMetafields: allMeta,
      productMetafieldCount: productAll.length,
      productAppOwnedHits: productAppOwned,
      productAllNamespaces: [...new Set(productAll.map((m) => m.namespace))],
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

router.get('/api/public/bundle-offers/scrape-grep', async (req, res) => {
  try {
    const handle = String(req.query.handle || 'leather-s-hooks-3-piece-set');
    const url = `https://metallbude.com/products/${handle}`;
    const r = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 Bundle-Resolver/1.0',
        Accept: 'text/html',
      },
    });
    const html = await r.text();

    const lines = html.split('\n');
    const grep = (re) => {
      const hits = [];
      lines.forEach((line, i) => {
        if (re.test(line)) {
          hits.push({ lineNo: i + 1, text: line.trim().slice(0, 600) });
        }
      });
      return hits.slice(0, 30);
    };

    return res.json({
      url,
      htmlLength: html.length,
      sectionheroes: grep(/section.?hero/i),
      shBundle: grep(/sh[-_]bundle|_sh.bundle/i),
      scriptSrcs: grep(/<script[^>]*src=["'][^"']*(?:sectionheroes|sh-bundle|bundle)/i),
      proxyUrls: grep(/\/apps\/sectionheroes|sectionheroes\.com|sh-bundle/i),
      idHits: grep(/gal5q|ikloj/),
      shopifyAnalytics: grep(/window\.Shopify\s*=/),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

router.get('/api/public/bundle-offers/scrape-full', async (req, res) => {
  try {
    const handle = String(req.query.handle || 'leather-s-hooks-3-piece-set');
    const url = `${STOREFRONT_BASE}/products/${handle}`;
    const html = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 Bundle-Resolver/1.0' },
    }).then((r) => r.text());

    const re = /<script[^>]*data-bundle-config[^>]*>([\s\S]*?)<\/script>/gi;
    const blocks = [];
    let m;
    while ((m = re.exec(html)) !== null) {
      try {
        blocks.push(JSON.parse(String(m[1] || '').trim()));
      } catch (e) {
        blocks.push({ _parseError: e.message, raw: String(m[1] || '').slice(0, 500) });
      }
    }
    return res.json({ url, blockCount: blocks.length, blocks });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

module.exports = router;
