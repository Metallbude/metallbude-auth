// =============================================================================
// accountDeletion — in-app "Konto löschen" (Google Play + App Store require
// that an app with customer accounts lets the customer delete it from inside
// the app).
//
// Everything outside this file is injected (Firestore, Storage bucket, the
// Shopify Admin GraphQL caller, the in-memory session maps), so the whole flow
// runs unchanged against the Firestore emulator + a fake Shopify in tests.
//
// What gets removed for the signed-in customer:
//   1. Shopify customer
//        - 0 orders  -> customerDelete (immediate)
//        - has orders -> customerRequestDataErasure (Shopify redacts the
//          personal data 10 days later; orders stay, anonymised)
//        - erasure not permitted (token lacks write_customer_data_erasure)
//          -> tag `app-account-deletion-requested` so staff can press
//          "Erase personal data" in the Shopify admin by hand.
//   2. Firestore wishlists (backend doc `wishlists/shopify_Customer_<id>` and
//      the app's shared wishlists with `customerId == <gid>`) + `uid_map`.
//   3. Styled-by-you posts by this email (post doc, likes subcollection, image
//      in Storage) and this email's likes on other people's posts.
//   4. Push: `push_subscriptions/<email>` + every `push_device_owner` entry.
//   5. Feedback docs sent with this email.
//   6. All app sessions + refresh tokens of this customer (memory + Firestore).
//
// The Shopify step runs first. If Shopify can't be reached at all, nothing
// else is touched and the caller gets an error, so the customer can retry.
// Every later step is best-effort and reported individually.
// =============================================================================

'use strict';

const crypto = require('crypto');
const { FieldValue } = require('firebase-admin/firestore');

const DELETION_TAG = 'app-account-deletion-requested';
const CUSTOMER_GID_RE = /^gid:\/\/shopify\/Customer\/(\d+)$/;
const FIRESTORE_BATCH_LIMIT = 400;
const MAX_POSTS_SCANNED_FOR_LIKES = 5000;

class ShopifyUnavailableError extends Error {}

const lower = (s) => String(s || '').trim().toLowerCase();

// Same rule as services/wishlist.js _sanitizeCustomerId.
const wishlistDocId = (customerId) =>
  String(customerId).replace(/[\/\:]/g, '_').replace(/^gid_+/, '');

const isAccessDenied = (errors) =>
  Array.isArray(errors) &&
  errors.some(
    (e) =>
      e?.extensions?.code === 'ACCESS_DENIED' ||
      /access denied|required access|write_customer_data_erasure/i.test(e?.message || '')
  );

// ---------------------------------------------------------------------------
// 1. Shopify
// ---------------------------------------------------------------------------

const Q_CUSTOMER = `
  query AccountDeletionCustomer($id: ID!) {
    customer(id: $id) { id defaultEmailAddress { emailAddress } numberOfOrders tags }
  }`;

const M_DELETE = `
  mutation AccountDeletionDelete($id: ID!) {
    customerDelete(input: { id: $id }) {
      deletedCustomerId
      userErrors { field message }
    }
  }`;

const M_ERASE = `
  mutation AccountDeletionErase($id: ID!) {
    customerRequestDataErasure(customerId: $id) {
      customerId
      userErrors { field message code }
    }
  }`;

const M_TAG = `
  mutation AccountDeletionTag($id: ID!, $tags: [String!]!) {
    tagsAdd(id: $id, tags: $tags) {
      node { id }
      userErrors { field message }
    }
  }`;

async function callShopify(shopify, query, variables) {
  try {
    return await shopify(query, variables);
  } catch (e) {
    throw new ShopifyUnavailableError(e?.message || String(e));
  }
}

async function removeShopifyCustomer({ shopify, customerId, email, log }) {
  if (!CUSTOMER_GID_RE.test(String(customerId || ''))) {
    // Sessions created while Shopify was unreachable carry a random fake id.
    return { status: 'not_a_shopify_customer' };
  }

  const lookup = await callShopify(shopify, Q_CUSTOMER, { id: customerId });
  if (lookup?.errors?.length) {
    throw new ShopifyUnavailableError(`lookup: ${JSON.stringify(lookup.errors)}`);
  }
  const customer = lookup?.data?.customer;
  if (!customer) return { status: 'not_found' };

  // Defence in depth: never touch a Shopify customer whose email isn't the
  // one this session logged in with.
  if (lower(customer.defaultEmailAddress?.emailAddress) !== lower(email)) {
    log(`⚠️ [DELETE-ACCOUNT] Shopify email mismatch for ${customerId} — Shopify left untouched`);
    return { status: 'skipped_email_mismatch' };
  }

  const orders = Number(customer.numberOfOrders || 0);

  if (orders === 0) {
    const del = await callShopify(shopify, M_DELETE, { id: customerId });
    const errs = del?.data?.customerDelete?.userErrors || [];
    if (!del?.errors?.length && !errs.length && del?.data?.customerDelete?.deletedCustomerId) {
      return { status: 'deleted', orders };
    }
    log(`⚠️ [DELETE-ACCOUNT] customerDelete refused (${JSON.stringify(del?.errors || errs)}) — trying erasure`);
  }

  const erase = await callShopify(shopify, M_ERASE, { id: customerId });
  const eraseErrs = erase?.data?.customerRequestDataErasure?.userErrors || [];
  if (!erase?.errors?.length && !eraseErrs.length) {
    // Tag too, so the pending erasure is visible in the admin for 10 days.
    await callShopify(shopify, M_TAG, { id: customerId, tags: [DELETION_TAG] }).catch(() => {});
    return { status: 'erasure_requested', orders };
  }

  const reason = erase?.errors?.length
    ? (isAccessDenied(erase.errors) ? 'missing_scope' : JSON.stringify(erase.errors))
    : JSON.stringify(eraseErrs);
  log(`⚠️ [DELETE-ACCOUNT] Erasure request failed (${reason}) — tagging for manual erasure`);

  const tag = await callShopify(shopify, M_TAG, { id: customerId, tags: [DELETION_TAG] });
  const tagErrs = tag?.data?.tagsAdd?.userErrors || [];
  if (tag?.errors?.length || tagErrs.length) {
    throw new ShopifyUnavailableError(
      `could not record deletion request: ${JSON.stringify(tag?.errors || tagErrs)}`
    );
  }
  return { status: 'manual_erasure_pending', orders, reason };
}

// ---------------------------------------------------------------------------
// Firestore helpers
// ---------------------------------------------------------------------------

async function deleteRefs(db, refs) {
  let n = 0;
  for (let i = 0; i < refs.length; i += FIRESTORE_BATCH_LIMIT) {
    const batch = db.batch();
    for (const ref of refs.slice(i, i + FIRESTORE_BATCH_LIMIT)) batch.delete(ref);
    await batch.commit();
    n += Math.min(FIRESTORE_BATCH_LIMIT, refs.length - i);
  }
  return n;
}

async function refsWhere(db, collection, field, values) {
  const seen = new Map();
  for (const v of [...new Set(values.filter(Boolean))]) {
    const snap = await db.collection(collection).where(field, '==', v).get();
    snap.docs.forEach((d) => seen.set(d.ref.path, d.ref));
  }
  return [...seen.values()];
}

// Firebase Storage download URL -> object path
// https://firebasestorage.googleapis.com/v0/b/<bucket>/o/<urlencoded path>?alt=media&token=…
function storagePathFromUrl(url) {
  const m = /\/o\/([^?]+)/.exec(String(url || ''));
  return m ? decodeURIComponent(m[1]) : null;
}

// ---------------------------------------------------------------------------
// 2–5. App data
// ---------------------------------------------------------------------------

async function deleteWishlists({ db, customerId }) {
  const refs = [db.collection('wishlists').doc(wishlistDocId(customerId))];
  refs.push(...(await refsWhere(db, 'wishlists', 'customerId', [customerId])));
  // uid_map is keyed by the customer id (the app writes the raw id; slashes
  // make the raw gid an invalid doc id, so the sanitised form is checked too).
  refs.push(db.collection('uid_map').doc(wishlistDocId(customerId)));
  const unique = [...new Map(refs.map((r) => [r.path, r])).values()];
  const existing = (await db.getAll(...unique)).filter((s) => s.exists).map((s) => s.ref);
  return { deleted: await deleteRefs(db, existing) };
}

async function deleteStyledByYou({ db, bucket, email, log }) {
  const emails = [email, lower(email)];
  const posts = await refsWhere(db, 'styled_by_you_posts', 'email', emails);

  let images = 0;
  let ownLikes = 0;
  for (const ref of posts) {
    const snap = await ref.get();
    const path = storagePathFromUrl(snap.get('imageUrl'));
    if (path && bucket) {
      try {
        await bucket.file(path).delete({ ignoreNotFound: true });
        images++;
      } catch (e) {
        log(`⚠️ [DELETE-ACCOUNT] image delete failed (${path}): ${e.message}`);
      }
    }
    const likes = await ref.collection('likes').listDocuments();
    ownLikes += await deleteRefs(db, likes);
  }
  const postsDeleted = await deleteRefs(db, posts);

  // This person's likes on other people's posts: like doc id = lowercased email.
  const deletedPaths = new Set(posts.map((r) => r.path));
  const allPosts = await db
    .collection('styled_by_you_posts')
    .select()
    .limit(MAX_POSTS_SCANNED_FOR_LIKES)
    .get();
  const likeRefs = allPosts.docs
    .filter((d) => !deletedPaths.has(d.ref.path))
    .map((d) => d.ref.collection('likes').doc(lower(email)));
  let likesRemoved = 0;
  if (likeRefs.length) {
    const likeSnaps = await db.getAll(...likeRefs);
    for (const s of likeSnaps.filter((x) => x.exists)) {
      const postRef = s.ref.parent.parent;
      const batch = db.batch();
      batch.delete(s.ref);
      batch.update(postRef, { likesCount: FieldValue.increment(-1) });
      await batch.commit();
      likesRemoved++;
    }
  }

  return { posts: postsDeleted, images, likesOnOwnPosts: ownLikes, likesOnOtherPosts: likesRemoved };
}

async function deletePush({ db, email, memoryStore }) {
  const key = lower(email);
  const subRef = db.collection('push_subscriptions').doc(key);
  const subSnap = await subRef.get();
  const ids = new Set();
  if (subSnap.exists) {
    const data = subSnap.data() || {};
    if (data.subscriptionId) ids.add(data.subscriptionId);
    (data.devices || []).forEach((d) => d?.subscriptionId && ids.add(d.subscriptionId));
  }

  const ownerRefs = new Map();
  (await refsWhere(db, 'push_device_owner', 'email', [key])).forEach((r) => ownerRefs.set(r.path, r));
  if (ids.size) {
    const snaps = await db.getAll(...[...ids].map((id) => db.collection('push_device_owner').doc(id)));
    // Only drop ownership that still points at this email (the phone may
    // already belong to someone else after an account switch).
    snaps
      .filter((s) => s.exists && lower(s.get('email')) === key)
      .forEach((s) => ownerRefs.set(s.ref.path, s.ref));
  }

  const toDelete = [...ownerRefs.values()];
  if (subSnap.exists) toDelete.push(subRef);
  const deleted = await deleteRefs(db, toDelete);

  if (memoryStore && memoryStore[key]) delete memoryStore[key];
  return { subscriptionDoc: subSnap.exists, deviceOwners: ownerRefs.size, deleted };
}

async function deleteFeedback({ db, email }) {
  const refs = await refsWhere(db, 'feedback', 'email', [email, lower(email)]);
  return { deleted: await deleteRefs(db, refs) };
}

// ---------------------------------------------------------------------------
// 6. Sessions
// ---------------------------------------------------------------------------

async function revokeSessions({ db, email, customerId, sessions, refreshTokens, persist }) {
  const key = lower(email);
  const matches = (s) => s && (lower(s.email) === key || (customerId && s.customerId === customerId));

  let memory = 0;
  for (const [token, s] of sessions) if (matches(s)) { sessions.delete(token); memory++; }
  for (const [token, r] of refreshTokens) if (matches(r)) { refreshTokens.delete(token); memory++; }
  if (persist) await persist();

  let durable = 0;
  if (db) {
    for (const col of ['app_sessions', 'app_refresh_tokens']) {
      const refs = new Map();
      // Sessions store the email exactly as typed at login.
      (await refsWhere(db, col, 'email', [email, key])).forEach((r) => refs.set(r.path, r));
      if (customerId) (await refsWhere(db, col, 'customerId', [customerId])).forEach((r) => refs.set(r.path, r));
      durable += await deleteRefs(db, [...refs.values()]);
    }
  }
  return { memory, durable };
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

async function deleteCustomerAccount({
  email,
  customerId,
  db,
  bucket,
  shopify,
  sessions,
  refreshTokens,
  persistSessions,
  pushMemoryStore,
  meta = {},
  log = console.log,
}) {
  if (!email) throw new Error('email required');

  const report = { shopify: null, steps: {} };

  // 1. Shopify first: if it can't be reached, abort before anything else.
  report.shopify = shopify
    ? await removeShopifyCustomer({ shopify, customerId, email, log })
    : { status: 'shopify_not_configured' };

  const step = async (name, fn) => {
    try {
      report.steps[name] = { ok: true, ...(await fn()) };
    } catch (e) {
      log(`❌ [DELETE-ACCOUNT] ${name} failed: ${e.message}`);
      report.steps[name] = { ok: false, error: e.message };
    }
  };

  if (db) {
    if (customerId) await step('wishlists', () => deleteWishlists({ db, customerId }));
    await step('styledByYou', () => deleteStyledByYou({ db, bucket, email, log }));
    await step('push', () => deletePush({ db, email, memoryStore: pushMemoryStore }));
    await step('feedback', () => deleteFeedback({ db, email }));
  } else {
    report.steps.firestore = { ok: false, error: 'firestore_not_configured' };
  }

  // Sessions last: the request's own token dies here.
  await step('sessions', () =>
    revokeSessions({ db, email, customerId, sessions, refreshTokens, persist: persistSessions })
  );

  // Audit trail without personal data: hash of the email + numeric Shopify id
  // (needed to follow up a pending manual erasure).
  if (db) {
    try {
      const m = CUSTOMER_GID_RE.exec(String(customerId || ''));
      await db.collection('account_deletions').add({
        emailSha256: crypto.createHash('sha256').update(lower(email)).digest('hex'),
        shopifyCustomerId: m ? m[1] : null,
        shopifyStatus: report.shopify.status,
        stepsFailed: Object.entries(report.steps).filter(([, v]) => !v.ok).map(([k]) => k),
        platform: meta.platform || null,
        appVersion: meta.appVersion || null,
        requestedAt: new Date().toISOString(),
      });
    } catch (e) {
      log(`⚠️ [DELETE-ACCOUNT] audit write failed: ${e.message}`);
    }
  }

  return report;
}

module.exports = {
  deleteCustomerAccount,
  ShopifyUnavailableError,
  DELETION_TAG,
  // exported for tests
  _internal: { removeShopifyCustomer, storagePathFromUrl, wishlistDocId },
};
