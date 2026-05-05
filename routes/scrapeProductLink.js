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

// ---------------------------------------------------------------------------
// HTML → plain text for the AI fallback. Strips scripts/styles/tags and
// caps length so we don't blow up the prompt.
// ---------------------------------------------------------------------------
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
    'You extract product details from a webpage so a furniture app can pre-fill a "save item" form. ' +
    'Reply with JSON only that matches the provided schema. ' +
    'Use null for any field you cannot confidently determine from the page text. Do not invent values. ' +
    'For price, return a number with no currency symbol. ' +
    'For currency, return a 3-letter ISO code. ' +
    'For dimensions, prefer the format "WxDxH cm" (or whatever units the page uses). ' +
    'Keep description under 200 characters.';

  const userText =
    `URL: ${urlHref}\n\n` +
    `Already extracted from OpenGraph (do NOT contradict, only fill gaps):\n` +
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

      const ogData = extractOgProduct(html, parsedUrl);

      // Treat OG as "good enough" only if we got at least a name AND either
      // an image or a price. Otherwise fall through to AI to fill the gaps.
      const ogConfident =
        !!ogData.name && (!!ogData.imageUrl || ogData.price != null);

      let aiData = {};
      let source = 'og';
      if (!ogConfident && process.env.GEMINI_API_KEY) {
        try {
          const text = htmlToText(html);
          aiData = await callGeminiForProduct(text, parsedUrl.href, ogData);
          source = ogData.name || ogData.imageUrl ? 'mixed' : 'ai';
        } catch (err) {
          // Don't fail the whole call — return whatever OG gave us.
          console.warn(
            `[scrape-product-link] AI fallback failed host=${parsedUrl.host}:`,
            err.message,
          );
        }
      }

      const payload = {
        name: ogData.name || aiData.name || null,
        brand: ogData.brand || aiData.brand || null,
        price:
          ogData.price != null ? ogData.price : aiData.price ?? null,
        currency: ogData.currency || aiData.currency || null,
        imageUrl: ogData.imageUrl || aiData.imageUrl || null,
        where: parsedUrl.host,
        material: aiData.material || null,
        dimensions: aiData.dimensions || null,
        description: ogData.description || aiData.description || null,
        source,
      };

      cacheSet(cacheKey, payload);
      console.log(
        `[scrape-product-link] host=${parsedUrl.host} source=${source} ` +
          `name=${payload.name ? '✓' : '✗'} price=${payload.price != null ? '✓' : '✗'} ` +
          `image=${payload.imageUrl ? '✓' : '✗'}`,
      );
      return res.json(payload);
    },
  );

  return router;
};
