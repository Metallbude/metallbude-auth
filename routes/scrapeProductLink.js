// =============================================================================
// scrapeProductLink — My Home "Other brand" link auto-fill.
//
// Authenticated app users paste a product URL on the Add Item form. We fetch
// the page server-side (with a proper UA, no CORS), pull OpenGraph /
// product:* meta out of the HTML with regex, and fall back to Gemini 2.5
// Flash Lite to fill any remaining gaps. Returns a normalised object the
// Flutter client can drop into the form.
//
// Style notes (matches existing routes/bundleOffers.js):
//   - express.Router(), no new dependencies (no cheerio, no SDK).
//   - Gemini called via REST with axios, mirroring the existing
//     callGeminiWithRetry pattern in index.js.
//   - In-memory TTL cache so refresh-spamming the same URL is cheap.
//
// Mounted from index.js as a factory so the inline `authenticateAppToken`
// middleware can be passed in without refactoring it out:
//   app.use(require('./routes/scrapeProductLink')(authenticateAppToken));
//
// Env: GEMINI_API_KEY (already set in Render). If missing we skip the AI
// fallback gracefully and return whatever OG gave us.
// =============================================================================

const express = require('express');
const axios = require('axios');

const router = express.Router();

const SCRAPE_FETCH_TIMEOUT_MS = 8000;
const SCRAPE_AI_TIMEOUT_MS = 12000;
const SCRAPE_USER_AGENT =
  'Mozilla/5.0 (compatible; MetallbudeBot/1.0; +https://metallbude.com)';
const SCRAPE_AI_TEXT_BUDGET = 8000;
const SCRAPE_AI_MODEL = 'gemini-2.5-flash-lite';
const SCRAPE_GEMINI_URL = (model, key) =>
  `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;

const SCRAPE_CACHE_TTL_MS = 5 * 60 * 1000;
const scrapeCache = new Map();

function cacheGet(url) {
  const entry = scrapeCache.get(url);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    scrapeCache.delete(url);
    return null;
  }
  return entry.value;
}

function cacheSet(url, value) {
  scrapeCache.set(url, { value, expiresAt: Date.now() + SCRAPE_CACHE_TTL_MS });
}

// ---------------------------------------------------------------------------
// HTTP fetch with timeout. Uses global fetch (Node 18+) like other routes.
// ---------------------------------------------------------------------------
async function fetchHtml(parsedUrl) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), SCRAPE_FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(parsedUrl.href, {
      headers: {
        'User-Agent': SCRAPE_USER_AGENT,
        'Accept-Language': 'en,de;q=0.8',
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      redirect: 'follow',
      signal: ctrl.signal,
    });
    if (!res.ok) {
      const err = new Error(`upstream_${res.status}`);
      err.status = res.status;
      throw err;
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Regex-based OpenGraph / product meta extraction. We avoid pulling in
// cheerio just for this — the bundleOffers route uses the same approach.
// ---------------------------------------------------------------------------
function extractMeta(html, attr, value) {
  // Matches both <meta property="..." content="..."> and the reverse order.
  // Case-insensitive, allows single or double quotes.
  const safe = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re1 = new RegExp(
    `<meta[^>]+${attr}\\s*=\\s*["']${safe}["'][^>]*content\\s*=\\s*["']([^"']*)["']`,
    'i',
  );
  const re2 = new RegExp(
    `<meta[^>]+content\\s*=\\s*["']([^"']*)["'][^>]*${attr}\\s*=\\s*["']${safe}["']`,
    'i',
  );
  const m = html.match(re1) || html.match(re2);
  return m && m[1] ? m[1].trim() : null;
}

function extractTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return null;
  return m[1].replace(/\s+/g, ' ').trim() || null;
}

// ---------------------------------------------------------------------------
// JSON-LD structured data (`<script type="application/ld+json">`).
// Most major e-commerce sites embed schema.org Product blocks here that are
// far richer than OG tags — brand, price, material, and sometimes
// dimensions (via additionalProperty / depth/height/width). We pull all
// LD blocks, walk @graph arrays, and return the first Product-shaped
// object we find.
// ---------------------------------------------------------------------------
function extractJsonLd(html) {
  const out = [];
  const re =
    /<script[^>]+type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const body = m[1].trim();
    if (!body) continue;
    try {
      const parsed = JSON.parse(body);
      out.push(parsed);
    } catch (_) {
      // Some sites embed slightly broken JSON-LD (trailing commas, raw
      // line breaks in strings). We swallow and move on — OG + Gemini
      // will still fire.
    }
  }
  return out;
}

function findProductNode(node) {
  if (!node || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = findProductNode(child);
      if (found) return found;
    }
    return null;
  }
  const type = node['@type'];
  const types = Array.isArray(type) ? type : [type];
  if (types.some((t) => typeof t === 'string' && /product/i.test(t))) {
    return node;
  }
  if (Array.isArray(node['@graph'])) {
    return findProductNode(node['@graph']);
  }
  return null;
}

function firstNonEmpty(...values) {
  for (const v of values) {
    if (v == null) continue;
    if (typeof v === 'string' && v.trim() === '') continue;
    return v;
  }
  return null;
}

function extractLdProduct(html, urlObj) {
  const blocks = extractJsonLd(html);
  let product = null;
  for (const block of blocks) {
    const found = findProductNode(block);
    if (found) {
      product = found;
      break;
    }
  }
  if (!product) return {};

  const name = typeof product.name === 'string' ? product.name.trim() : null;

  // brand can be a string OR an object {name: 'X'} OR an array of either.
  let brand = null;
  const b = product.brand;
  if (typeof b === 'string') brand = b.trim();
  else if (Array.isArray(b) && b.length) {
    const first = b[0];
    brand =
      typeof first === 'string' ? first.trim() : first?.name?.toString().trim() || null;
  } else if (b && typeof b === 'object') {
    brand = b.name ? b.name.toString().trim() : null;
  }

  // image can be string | string[] | ImageObject | ImageObject[]
  let imageUrl = null;
  const img = product.image;
  const pickImg = (v) => {
    if (!v) return null;
    if (typeof v === 'string') return v;
    if (typeof v === 'object') return v.url || v.contentUrl || null;
    return null;
  };
  if (Array.isArray(img)) imageUrl = pickImg(img[0]);
  else imageUrl = pickImg(img);
  if (imageUrl) {
    if (imageUrl.startsWith('//')) imageUrl = `https:${imageUrl}`;
    else if (imageUrl.startsWith('/'))
      imageUrl = `${urlObj.origin}${imageUrl}`;
  }

  // offers can be Offer | AggregateOffer | array of either.
  let price = null;
  let currency = null;
  const offers = product.offers;
  const pickOffer = (o) => {
    if (!o || typeof o !== 'object') return;
    const p = firstNonEmpty(o.price, o.lowPrice, o.highPrice);
    if (p != null && price == null) {
      const n =
        typeof p === 'number'
          ? p
          : parseFloat(String(p).replace(/[^\d,.\-]/g, '').replace(',', '.'));
      if (!isNaN(n)) price = n;
    }
    if (!currency && o.priceCurrency) currency = String(o.priceCurrency).trim();
  };
  if (Array.isArray(offers)) offers.forEach(pickOffer);
  else pickOffer(offers);

  const description =
    typeof product.description === 'string'
      ? product.description.trim()
      : null;

  // Material: schema.org `material` is sometimes a string, sometimes a
  // Product/URL reference. Take string form only.
  let material = null;
  if (typeof product.material === 'string') material = product.material.trim();

  // Dimensions: schema.org models width/depth/height as QuantitativeValue
  // ({value, unitCode}). If at least one is present, build a "WxDxH unit"
  // string. Many furniture sites also stash dimensions in
  // additionalProperty as PropertyValue objects — try those too.
  const dimensions = extractLdDimensions(product);

  return {
    name: name || null,
    brand: brand || null,
    price,
    currency,
    imageUrl: imageUrl || null,
    description: description || null,
    material,
    dimensions,
  };
}

function extractLdDimensions(product) {
  const qv = (v) => {
    if (!v) return null;
    if (typeof v === 'number' || typeof v === 'string') return String(v);
    if (typeof v === 'object') {
      const val = v.value ?? null;
      if (val == null) return null;
      const unit = v.unitCode || v.unitText || '';
      // unitCode is UN/CEFACT (CMT = cm, MTR = m, INH = inch). Map a couple.
      const unitMap = { CMT: 'cm', MTR: 'm', INH: 'in', MMT: 'mm' };
      const u = unitMap[unit] || unit || '';
      return u ? `${val}${u}` : String(val);
    }
    return null;
  };
  const w = qv(product.width);
  const d = qv(product.depth);
  const h = qv(product.height);
  if (w || d || h) {
    return [w, d, h].filter(Boolean).join('x');
  }
  // additionalProperty fallback: array of {name, value, unitText}.
  if (Array.isArray(product.additionalProperty)) {
    const map = {};
    for (const p of product.additionalProperty) {
      if (!p || typeof p !== 'object') continue;
      const nm = String(p.name || '').toLowerCase();
      if (!nm) continue;
      const val = p.value != null ? String(p.value) : null;
      if (!val) continue;
      const unit = p.unitText || p.unitCode || '';
      const v = unit ? `${val}${unit}` : val;
      if (/^(width|breite|larg)/.test(nm)) map.w = v;
      else if (/^(depth|tiefe|prof)/.test(nm)) map.d = v;
      else if (/^(height|höhe|haut)/.test(nm)) map.h = v;
    }
    if (map.w || map.d || map.h) {
      return [map.w, map.d, map.h].filter(Boolean).join('x');
    }
  }
  return null;
}

function extractOgProduct(html, urlObj) {
  const name =
    extractMeta(html, 'property', 'og:title') ||
    extractMeta(html, 'name', 'twitter:title') ||
    extractTitle(html) ||
    null;
  const description =
    extractMeta(html, 'property', 'og:description') ||
    extractMeta(html, 'name', 'description') ||
    null;

  let imageUrl =
    extractMeta(html, 'property', 'og:image:secure_url') ||
    extractMeta(html, 'property', 'og:image') ||
    extractMeta(html, 'name', 'twitter:image') ||
    null;
  if (imageUrl) {
    if (imageUrl.startsWith('//')) imageUrl = `https:${imageUrl}`;
    else if (imageUrl.startsWith('/')) imageUrl = `${urlObj.origin}${imageUrl}`;
  }

  const brand =
    extractMeta(html, 'property', 'product:brand') ||
    extractMeta(html, 'name', 'product:brand') ||
    extractMeta(html, 'property', 'og:site_name') ||
    null;

  const priceStr =
    extractMeta(html, 'property', 'product:price:amount') ||
    extractMeta(html, 'property', 'og:price:amount') ||
    extractMeta(html, 'itemprop', 'price') ||
    null;
  const currency =
    extractMeta(html, 'property', 'product:price:currency') ||
    extractMeta(html, 'property', 'og:price:currency') ||
    extractMeta(html, 'itemprop', 'priceCurrency') ||
    null;

  let price = null;
  if (priceStr) {
    const cleaned = priceStr.replace(/[^\d,.\-]/g, '').replace(',', '.');
    const n = parseFloat(cleaned);
    if (!isNaN(n)) price = n;
  }

  return {
    name: name || null,
    brand,
    price,
    currency,
    imageUrl,
    description,
  };
}

// Merge a higher-priority structured source over a lower-priority one.
// Used to layer JSON-LD (preferred) on top of OG meta. A field on the
// override only wins when it's non-empty/non-null.
function mergeStructured(base, override) {
  const out = { ...base };
  for (const k of Object.keys(override)) {
    const v = override[k];
    if (v == null) continue;
    if (typeof v === 'string' && v.trim() === '') continue;
    out[k] = v;
  }
  return out;
}
function htmlToText(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, SCRAPE_AI_TEXT_BUDGET);
}

// ---------------------------------------------------------------------------
// Gemini call via REST. Mirrors the existing `callGemini*` helpers in
// index.js — no @google/generative-ai SDK needed.
// ---------------------------------------------------------------------------
async function callGeminiForProduct(text, urlHref, ogData) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return {};

  const known = {
    name: ogData.name || null,
    brand: ogData.brand || null,
    price: ogData.price ?? null,
    currency: ogData.currency || null,
    imageUrl: ogData.imageUrl || null,
    description: ogData.description || null,
    material: ogData.material || null,
    dimensions: ogData.dimensions || null,
  };

  // Schema-constrained JSON output. Every field is nullable and none are
  // required — the model returns null when it can't confidently determine
  // a value. This dramatically reduces hallucinated brand/price guesses.
  const responseSchema = {
    type: 'OBJECT',
    properties: {
      name: { type: 'STRING', nullable: true },
      brand: { type: 'STRING', nullable: true },
      price: { type: 'NUMBER', nullable: true },
      currency: { type: 'STRING', nullable: true },
      material: { type: 'STRING', nullable: true },
      dimensions: { type: 'STRING', nullable: true },
      description: { type: 'STRING', nullable: true },
    },
  };

  const systemInstruction =
    'You extract product details from a product webpage so a furniture app can pre-fill a "save item" form. ' +
    'Reply with JSON only that matches the provided schema. Every field is optional and may be null. ' +
    'Use null whenever you cannot confidently determine a value from the page text — do not guess and do not invent values. ' +
    '\n\nField-by-field rules:\n' +
    '• name: the product\'s display name (e.g. "Eames Lounge Chair"). Strip site/brand suffixes like " – BrandName" or " | Online Shop".\n' +
    '• brand: the manufacturer or maker. Look for "by X", "Brand:", "Marke:", "Hersteller:", site headers, or product:brand metadata. Prefer the maker over the retailer.\n' +
    '• price: the current sale price as a plain number with no currency symbol and no thousand separators. If multiple prices appear, prefer the current/sale price over the original/strikethrough price.\n' +
    '• currency: 3-letter ISO 4217 code (EUR, USD, GBP, CHF, etc.). Infer from the currency symbol if not explicit.\n' +
    '• material: the primary surface material(s). Prefer the MOST SPECIFIC description, not a generic category. "Eiche massiv geölt" beats "Holz"; "powder-coated steel" beats "metal"; "100% Leinen" beats "Stoff". Look in: product description prose ("Aus massiver Eiche..."); spec/details tables; German labels like "Material:", "Werkstoff:", "Bezug:", "Holzart:", "Oberfläche:"; English labels like "Material:", "Finish:", "Upholstery:". If multiple distinct materials are listed (e.g. frame + upholstery), join them with ", ".\n' +
    '• dimensions: prefer the format "WxDxH cm" (or "BxTxH cm" for German pages). Look in: spec tables with rows labelled "Breite"/"Tiefe"/"Höhe"/"Länge" or "Width"/"Depth"/"Height"/"Length"; inline phrases like "Maße: 120 x 80 x 75 cm" or "Abmessungen:"; combined strings like "B 120 cm × T 80 cm × H 75 cm". Convert any of those to the compact "120x80x75 cm" form (or whatever units the page actually uses — don\'t convert mm to cm or in to cm). If only one dimension is given (e.g. diameter for a round table), return it labelled, e.g. "Ø 90 cm".\n' +
    '• description: a short sentence summarising the product. Maximum 200 characters. No marketing fluff.\n' +
    '\nReview every field carefully. Many product pages contain all of these in a spec/details table or a "Material & dimensions" section — read the WHOLE page text before deciding a field is null. Material and dimensions in particular are commonly buried in description prose or German spec tables and are easy to miss on a quick pass.';

  const userText =
    `URL: ${urlHref}\n\n` +
    `Already extracted from the page's structured data (do NOT contradict; only fill the null/missing slots):\n` +
    `${JSON.stringify(known)}\n\n` +
    `Page text (truncated):\n${text}`;

  const body = {
    systemInstruction: {
      role: 'system',
      parts: [{ text: systemInstruction }],
    },
    contents: [
      {
        role: 'user',
        parts: [{ text: userText }],
      },
    ],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema,
      temperature: 0,
      maxOutputTokens: 400,
    },
  };

  const resp = await axios.post(
    SCRAPE_GEMINI_URL(SCRAPE_AI_MODEL, apiKey),
    body,
    {
      headers: { 'Content-Type': 'application/json' },
      timeout: SCRAPE_AI_TIMEOUT_MS,
      // We handle non-2xx ourselves so we don't blow up the request.
      validateStatus: () => true,
    },
  );

  if (resp.status < 200 || resp.status >= 300) {
    console.warn(
      `[scrape-product-link] gemini http ${resp.status}:`,
      typeof resp.data === 'string' ? resp.data.slice(0, 200) : resp.data,
    );
    return {};
  }

  // The REST shape: { candidates: [ { content: { parts: [ { text } ] }, finishReason } ] }
  const candidate = resp.data?.candidates?.[0];
  if (!candidate) return {};
  if (candidate.finishReason && candidate.finishReason !== 'STOP') {
    console.warn(
      `[scrape-product-link] gemini finishReason=${candidate.finishReason}`,
    );
  }
  const raw = candidate.content?.parts?.[0]?.text || '';
  // TEMP DEBUG: dump payload + raw response for one test cycle. Remove after diagnosis.
  console.log(
    `[scrape-product-link][debug] text length=${text.length}\n--- TEXT TO GEMINI (first 3000) ---\n${text.slice(0, 3000)}\n--- GEMINI RAW RESPONSE ---\n${raw}\n--- END DEBUG ---`,
  );
  return parseAiJson(raw);
}

// ---------------------------------------------------------------------------
// Defensive JSON parsing. Even with responseMimeType=json + a schema,
// Gemini occasionally wraps output in ```json fences, prefixes prose, or
// returns truncated JSON when it hits maxOutputTokens. We strip the most
// common wrappers, then fall back to slicing the first balanced object.
// ---------------------------------------------------------------------------
function parseAiJson(raw) {
  if (!raw || typeof raw !== 'string') return {};
  let s = raw.trim();
  if (!s) return {};

  const fence = s.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fence) s = fence[1].trim();

  try {
    return normaliseAiResult(JSON.parse(s));
  } catch (_) {
    /* fall through to balanced-object scan */
  }

  const start = s.indexOf('{');
  if (start === -1) return {};
  let depth = 0;
  let end = -1;
  let inStr = false;
  let escape = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (escape) escape = false;
      else if (c === '\\') escape = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) return {};
  try {
    return normaliseAiResult(JSON.parse(s.slice(start, end + 1)));
  } catch (_) {
    return {};
  }
}

// Coerce types so the response shape matches what the client expects.
// Gemini sometimes returns "null" as a string or a price like "299,00 €".
function normaliseAiResult(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return {};
  const out = {};
  const strField = (k) => {
    const x = v[k];
    if (x == null) return;
    const s = String(x).trim();
    if (!s || s.toLowerCase() === 'null') return;
    out[k] = s;
  };
  strField('name');
  strField('brand');
  strField('currency');
  strField('material');
  strField('dimensions');
  strField('description');
  const p = v.price;
  if (typeof p === 'number' && isFinite(p)) {
    out.price = p;
  } else if (typeof p === 'string') {
    const cleaned = p.replace(/[^\d,.\-]/g, '').replace(',', '.');
    const n = parseFloat(cleaned);
    if (!isNaN(n)) out.price = n;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Route factory. Exported so index.js can pass in its inline auth middleware
// without us having to refactor it out. Mount with:
//   app.use(require('./routes/scrapeProductLink')(authenticateAppToken));
// ---------------------------------------------------------------------------
module.exports = function (authenticateAppToken) {
  router.post(
    '/customer/scrape-product-link',
    authenticateAppToken,
    async (req, res) => {
      const rawUrl =
        typeof req.body?.url === 'string' ? req.body.url.trim() : '';
      if (!rawUrl) {
        return res.status(400).json({ error: 'url_required' });
      }

      let parsedUrl;
      try {
        parsedUrl = new URL(
          rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`,
        );
      } catch (_) {
        return res.status(400).json({ error: 'invalid_url' });
      }
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return res.status(400).json({ error: 'invalid_scheme' });
      }

      const cacheKey = parsedUrl.href;
      const cached = cacheGet(cacheKey);
      if (cached) {
        return res.json({ ...cached, cached: true });
      }

      let html;
      try {
        html = await fetchHtml(parsedUrl);
      } catch (err) {
        console.warn(
          `[scrape-product-link] fetch failed host=${parsedUrl.host}:`,
          err.message,
        );
        return res
          .status(502)
          .json({ error: 'fetch_failed', detail: err.message });
      }

      // Layer JSON-LD (schema.org Product) over OG meta. JSON-LD is
      // typically far more complete — brand, price, material, dimensions
      // are usually only present here. We treat JSON-LD as authoritative
      // when its fields are non-null; OG fills any gaps.
      const ogOnly = extractOgProduct(html, parsedUrl);
      const ldData = extractLdProduct(html, parsedUrl);
      const ogData = mergeStructured(ogOnly, ldData);

      // Trigger AI when the structured-data pass left ANY of the six core
      // fields empty. Material and dimensions are very rarely present in
      // OG meta and often missing from JSON-LD, but typically findable in
      // the page's description text or spec table — exactly Gemini's
      // strength. Cost is negligible (Flash Lite, sub-cent per call) and
      // the user is already watching a spinner.
      const coreMissing =
        !ogData.name ||
        !ogData.brand ||
        ogData.price == null ||
        !ogData.imageUrl ||
        !ogData.material ||
        !ogData.dimensions;
      const ogConfident = !coreMissing;

      // Track which structured pass actually contributed something so the
      // `source` label in the response is honest.
      const sourcesUsed = [];
      if (
        ogOnly.name ||
        ogOnly.brand ||
        ogOnly.price != null ||
        ogOnly.imageUrl
      ) {
        sourcesUsed.push('og');
      }
      if (
        ldData.name ||
        ldData.brand ||
        ldData.price != null ||
        ldData.imageUrl ||
        ldData.material ||
        ldData.dimensions
      ) {
        sourcesUsed.push('ld');
      }

      let aiData = {};
      if (!ogConfident && process.env.GEMINI_API_KEY) {
        try {
          const text = htmlToText(html);
          aiData = await callGeminiForProduct(text, parsedUrl.href, ogData);
          if (Object.keys(aiData).length) sourcesUsed.push('ai');
        } catch (err) {
          // Don't fail the whole call — return whatever structured data gave us.
          console.warn(
            `[scrape-product-link] AI fallback failed host=${parsedUrl.host}:`,
            err.message,
          );
        }
      }
      const source = sourcesUsed.join('+') || 'none';

      const payload = {
        name: ogData.name || aiData.name || null,
        brand: ogData.brand || aiData.brand || null,
        price:
          ogData.price != null ? ogData.price : aiData.price ?? null,
        currency: ogData.currency || aiData.currency || null,
        imageUrl: ogData.imageUrl || aiData.imageUrl || null,
        where: parsedUrl.host,
        material: ogData.material || aiData.material || null,
        dimensions: ogData.dimensions || aiData.dimensions || null,
        description: ogData.description || aiData.description || null,
        source,
      };

      cacheSet(cacheKey, payload);
      console.log(
        `[scrape-product-link] host=${parsedUrl.host} source=${source} ` +
          `name=${payload.name ? '✓' : '✗'} ` +
          `brand=${payload.brand ? '✓' : '✗'} ` +
          `price=${payload.price != null ? '✓' : '✗'} ` +
          `image=${payload.imageUrl ? '✓' : '✗'} ` +
          `material=${payload.material ? '✓' : '✗'} ` +
          `dimensions=${payload.dimensions ? '✓' : '✗'}`,
      );
      return res.json(payload);
    },
  );

  return router;
};
