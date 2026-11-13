// Delivery estimate ("Lieferzeit") for draft-order lines.
//
// On every normal checkout, the versanddauer checkout extension
// (shopify-app-delivery-highest-main/extensions/versanddauer-checkout/
// src/Checkout.jsx) stamps this property onto each line. It can't edit the
// lines of a draft-order checkout, so the app-price drafts get it stamped
// here, when the draft is created. This is a port of the extension's
// calculateDeliveryTime and its date helpers: same metafields, same
// wording, same date math. Keep the two in step.

const axios = require('axios');

// EU countries other than DE (DE itself ships without an offset).
const EU_COUNTRIES = [
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'GR', 'HU', 'IE',
  'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
];

const WEEK_WORDS =
  '(?:wochen?|weeks?|semaines?|semanas?|settimane?|weken?|tygodni[ea]?|uger?|veckor?)';
const WEEKS_RE = new RegExp(`^(\\d+)\\s*${WEEK_WORDS}$`, 'i');
const WEEKS_RANGE_RE = new RegExp(`^(\\d+)[-,](\\d+)\\s*${WEEK_WORDS}$`, 'i');

const DEFAULT_DISPLAY = {
  mode: 'days',
  format: 'medium',
  prefix: 'Lieferung am',
  rangeText: 'bis',
  daysText: 'Tage',
  weeksText: 'Wochen',
  circaText: 'ca.',
  immediateText: 'Sofort lieferbar',
  onRequestText: 'Lieferzeit auf Anfrage',
  showInWeeks: false,
  showYear: true,
};
const DEFAULT_MONTHS_SHORT = [
  'Jan', 'Feb', 'März', 'Apr', 'Mai', 'Juni', 'Juli', 'Aug', 'Sept', 'Okt', 'Nov', 'Dez',
];
const DEFAULT_MONTHS_LONG = [
  'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli', 'August',
  'September', 'Oktober', 'November', 'Dezember',
];
const DEFAULT_WEEKDAYS = ['So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa'];

// A huge metafield typo ("10000000") must not spin the event loop.
const MAX_BUSINESS_DAYS = 3660;

/**
 * The shop's delivery settings from the raw metafield values, resolved for
 * one checkout language (German fallback, like the extension).
 */
function parseDeliverySettings(raw, lang = 'de') {
  let display = { ...DEFAULT_DISPLAY };
  let translations = {};
  if (raw.displaySettings) {
    try {
      const parsed = JSON.parse(raw.displaySettings);
      display = { ...display, ...parsed };
      if (parsed.translations) translations = parsed.translations;
    } catch (_) {}
  }
  const t = translations[lang] || translations.de || {};
  for (const k of [
    'daysText', 'weeksText', 'circaText', 'prefix', 'rangeText', 'immediateText', 'onRequestText',
  ]) {
    if (t[k]) display[k] = t[k];
  }

  // The holidays metafield holds [{date, name}] entries. The extension
  // compares those to date strings, so it never actually skips a holiday;
  // here both shapes count, so drafts skip holidays as the list intends.
  const holidays = new Set();
  if (raw.holidays) {
    try {
      const parsed = JSON.parse(raw.holidays);
      for (const h of Array.isArray(parsed) ? parsed : []) {
        const date = typeof h === 'string' ? h : h?.date;
        if (typeof date === 'string') holidays.add(date.trim());
      }
    } catch (_) {}
  }

  return {
    display,
    t,
    translations,
    holidays,
    skipWeekends: raw.skipWeekends === 'true',
    euOffset: parseInt(raw.euOffset || '0', 10) || 0,
    nonEuOffset: parseInt(raw.nonEuOffset || '0', 10) || 0,
    propertyKey: t.deliveryPropertyKey || 'Lieferzeit',
  };
}

// A calendar day as a UTC-midnight Date. All date math here runs on the
// UTC fields, so the server's own timezone never shifts a day.
function calendarDay(year, monthIndex, day) {
  return new Date(Date.UTC(year, monthIndex, day));
}

// Today in the shop's timezone. The extension uses the buyer's local date;
// the buyers are in Europe and the shop runs on Europe/Berlin.
function shopToday(now = new Date(), timeZone = 'Europe/Berlin') {
  const parts = {};
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
  });
  for (const p of fmt.formatToParts(now)) parts[p.type] = p.value;
  return calendarDay(Number(parts.year), Number(parts.month) - 1, Number(parts.day));
}

function isNonDeliveryDay(date, s) {
  if (s.skipWeekends) {
    const day = date.getUTCDay();
    if (day === 0 || day === 6) return true;
  }
  return s.holidays.has(date.toISOString().slice(0, 10));
}

// `days` delivery days after `start`, skipping weekends/holidays per settings.
function addBusinessDays(start, days, s) {
  const result = new Date(start.getTime());
  const target = Math.min(days, MAX_BUSINESS_DAYS);
  let added = 0;
  while (added < target) {
    result.setUTCDate(result.getUTCDate() + 1);
    if (!isNonDeliveryDay(result, s)) added++;
  }
  return result;
}

function formatDate(date, format, t, showYear) {
  const months = t.monthsShort || DEFAULT_MONTHS_SHORT;
  const monthsLong = t.monthsLong || DEFAULT_MONTHS_LONG;
  const weekdays = t.weekdays || DEFAULT_WEEKDAYS;
  const d = date.getUTCDate();
  const m = date.getUTCMonth();
  const year = showYear !== false ? ` ${date.getUTCFullYear()}` : '';
  switch (format) {
    case 'short':
      return `${d}. ${months[m]}`;
    case 'long':
      return `${d}. ${monthsLong[m]}${year}`;
    case 'with_weekday':
      return `${weekdays[date.getUTCDay()]}, ${d}. ${months[m]}${year}`;
    case 'medium':
    default:
      return `${d}. ${months[m]}${year}`;
  }
}

/**
 * The property value for one variant's versanddauer metafield, e.g.
 * "1-3" -> "Erwartete Lieferung: 16. Nov bis 18. Nov". Mirrors the
 * extension's calculateDeliveryTime branch for branch.
 */
function deliveryText(value, countryCode, s, today) {
  const { display, t, translations } = s;
  const {
    mode, format, prefix, rangeText, daysText, weeksText, circaText,
    immediateText, onRequestText, showInWeeks, showYear,
  } = display;

  let countryOffset = 0;
  if (countryCode !== 'DE') {
    countryOffset = EU_COUNTRIES.includes(countryCode) ? s.euOffset : s.nonEuOffset;
  }

  let val = String(value).trim();
  const vl = val.toLowerCase();
  const span = (from, to) =>
    `${prefix} ${formatDate(from, format, t, showYear)} ${rangeText} ${formatDate(to, format, t, showYear)}`;

  // A fixed date (e.g. a restock): that day to three delivery days later.
  const iso = val.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (iso) {
    const start = calendarDay(Number(iso[1]), Number(iso[2]) - 1, Number(iso[3]));
    return span(start, addBusinessDays(start, 3, s));
  }

  // Weeks: "12 Wochen", "2-3 weeks", ...
  const weeks = val.match(WEEKS_RE);
  if (weeks) {
    const n = parseInt(weeks[1], 10);
    if (showInWeeks) return `${t.circaText || circaText} ${n} ${t.weeksText || weeksText}`;
    val = String(n * 7);
  }
  const weeksRange = val.match(WEEKS_RANGE_RE);
  if (weeksRange) {
    const from = parseInt(weeksRange[1], 10);
    const to = parseInt(weeksRange[2], 10);
    if (showInWeeks) return `${from}-${to} ${t.weeksText || weeksText}`;
    val = `${from * 7}-${to * 7}`;
  }

  // Immediate / on request, in any of the shop's languages.
  if (vl === 'sofort') return immediateText;
  if (vl === 'auf anfrage') return onRequestText;
  for (const lng of Object.keys(translations || {})) {
    const tr = translations[lng] || {};
    if (tr.immediateText && vl === String(tr.immediateText).toLowerCase()) return immediateText;
    if (tr.onRequestText && vl === String(tr.onRequestText).toLowerCase()) return onRequestText;
  }

  // Day range: "1-3"
  const range = val.match(/^(\d+)[-,](\d+)$/);
  if (range) {
    const min = parseInt(range[1], 10) + countryOffset;
    const max = parseInt(range[2], 10) + countryOffset;
    if (mode === 'date') {
      return span(addBusinessDays(today, min, s), addBusinessDays(today, max, s));
    }
    return `${min}-${max} ${daysText}`;
  }

  // Single number of days: "5"
  const single = val.match(/^(\d+)$/);
  if (single) {
    const n = parseInt(single[1], 10) + countryOffset;
    if (mode === 'date') {
      return `${prefix} ${formatDate(addBusinessDays(today, n, s), format, t, showYear)}`;
    }
    return `${circaText} ${n} ${daysText}`;
  }

  // Free text: only values with a number get the country offset noted.
  if (countryOffset > 0 && /\d/.test(val)) return `${val} (+${countryOffset} ${daysText})`;
  return val;
}

const DELIVERY_QUERY = `query($ids: [ID!]!) {
  shop {
    displaySettings: metafield(namespace: "custom", key: "versanddauer_display_settings") { value }
    holidays: metafield(namespace: "custom", key: "holidays") { value }
    skipWeekends: metafield(namespace: "custom", key: "skip_weekends") { value }
    euOffset: metafield(namespace: "custom", key: "versanddauer_eu_offset") { value }
    nonEuOffset: metafield(namespace: "custom", key: "versanddauer_non_eu_offset") { value }
  }
  nodes(ids: $ids) {
    ... on ProductVariant { id versanddauer: metafield(namespace: "custom", key: "versanddauer") { value } }
  }
}`;

/**
 * variantId -> { key, value } for every variant that has a delivery time
 * (the same variants the extension stamps), worded for `lang` and offset
 * for the shipping country.
 */
async function fetchDeliveryEstimates({
  adminUrl,
  headers,
  variantIds,
  countryCode = 'DE',
  lang = 'de',
  now = new Date(),
}) {
  const r = await axios.post(
    adminUrl,
    { query: DELIVERY_QUERY, variables: { ids: variantIds } },
    { headers, timeout: 5000 },
  );
  const out = new Map();
  const shop = r.data?.data?.shop;
  if (!shop) return out;
  const s = parseDeliverySettings(
    {
      displaySettings: shop.displaySettings?.value,
      holidays: shop.holidays?.value,
      skipWeekends: shop.skipWeekends?.value,
      euOffset: shop.euOffset?.value,
      nonEuOffset: shop.nonEuOffset?.value,
    },
    lang,
  );
  const today = shopToday(now);
  for (const n of r.data?.data?.nodes || []) {
    const raw = n?.versanddauer?.value;
    if (!n?.id || typeof raw !== 'string' || !raw.trim()) continue;
    try {
      const value = deliveryText(raw, countryCode, s, today);
      if (value) out.set(n.id, { key: s.propertyKey, value: value.slice(0, 255) });
    } catch (_) {}
  }
  return out;
}

module.exports = {
  fetchDeliveryEstimates,
  parseDeliverySettings,
  deliveryText,
  shopToday,
  DELIVERY_QUERY,
};
