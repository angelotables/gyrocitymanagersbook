const admin = require('firebase-admin');
admin.initializeApp();
const db = admin.firestore();
const auth = admin.auth();

// Keep this list in sync with the manager UIDs in your Firestore rules.
const MANAGER_UIDS = ['9ys8uO70MzUHiCerNDSx6TT22qm1']; // Alessandro
const EMAIL_DOMAIN = 'staff.gyrocity.app';
// A 4-digit PIN is the only secret; this just turns it into a valid (>=6 char) password.
const pw = (pin) => 'gc-' + pin + '-staff';

// Shared role accounts for the ordering app — not tied to any one person.
// 'owner' implies 'orders' too (broader access), matching the app's UI tiers.
const ROLE_UIDS = { orders: 'role_orders', owner: 'role_owner' };
const ROLE_EMAIL_DOMAIN = 'ordering.gyrocity.app';
const rolePw = (pin) => 'gc-' + pin + '-role';

function setCors(res) {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

async function rosterHasId(empId) {
  for (const st of ['astoria', 'macdougal']) {
    const snap = await db.doc('gyrocity/emp_' + st).get();
    if (snap.exists && (snap.data().list || []).some((e) => e.id === empId)) return true;
  }
  return false;
}

async function callerIsManager(req) {
  const authz = req.get('Authorization') || '';
  const idToken = authz.startsWith('Bearer ') ? authz.slice(7) : '';
  if (!idToken) return false;
  const decoded = await auth.verifyIdToken(idToken).catch(() => null);
  return !!(decoded && MANAGER_UIDS.includes(decoded.uid));
}

exports.staff = async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).send('');
  try {
    const body = req.body || {};
    const action = body.action || '';

    // Staff self-service: create a first-time PIN. Only for a real roster member
    // who doesn't already have a login. (If they forgot it, a manager resets it.)
    if (action === 'register') {
      const empId = String(body.empId || '');
      const pin = String(body.pin || '');
      if (!empId || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'Need a 4-digit PIN.' });
      if (!(await rosterHasId(empId))) return res.status(403).json({ error: 'Not on the roster — ask your manager.' });
      try {
        await auth.getUser(empId);
        return res.status(409).json({ error: 'You already have a PIN. Ask a manager to reset it if you forgot.' });
      } catch (e) { /* user-not-found -> ok to create */ }
      await auth.createUser({ uid: empId, email: empId + '@' + EMAIL_DOMAIN, password: pw(pin) });
      await auth.setCustomUserClaims(empId, { staff: true });
      return res.json({ ok: true });
    }

    // Manager-only: which roster members currently have a login.
    if (action === 'list') {
      if (!(await callerIsManager(req))) return res.status(403).json({ error: 'Managers only.' });
      const ids = [];
      for (const st of ['astoria', 'macdougal']) {
        const snap = await db.doc('gyrocity/emp_' + st).get();
        if (snap.exists) for (const e of (snap.data().list || [])) ids.push(e.id);
      }
      const withLogin = [];
      for (let i = 0; i < ids.length; i += 100) {
        const chunk = ids.slice(i, i + 100).map((uid) => ({ uid }));
        const r = await auth.getUsers(chunk);
        for (const u of r.users) withLogin.push(u.uid);
      }
      return res.json({ ok: true, withLogin });
    }

    // Manager-only: reset (staff can then set a new PIN) or terminate a login.
    if (action === 'reset' || action === 'terminate') {
      if (!(await callerIsManager(req))) return res.status(403).json({ error: 'Managers only.' });
      const empId = String(body.empId || '');
      if (!empId) return res.status(400).json({ error: 'Missing empId.' });
      try { await auth.deleteUser(empId); } catch (e) { /* already gone */ }
      return res.json({ ok: true });
    }

    // Manager-only: set or replace the Orders / Owner code for the ordering app.
    if (action === 'role-set') {
      if (!(await callerIsManager(req))) return res.status(403).json({ error: 'Managers only.' });
      const role = String(body.role || '');
      const pin = String(body.pin || '');
      if (!ROLE_UIDS[role]) return res.status(400).json({ error: 'Unknown role.' });
      if (!/^\d{4,}$/.test(pin)) return res.status(400).json({ error: 'Code must be at least 4 digits.' });
      const uid = ROLE_UIDS[role];
      const email = role + '@' + ROLE_EMAIL_DOMAIN;
      const password = rolePw(pin);
      try {
        await auth.updateUser(uid, { password });
      } catch (e) {
        await auth.createUser({ uid, email, password });
      }
      await auth.setCustomUserClaims(uid, { orders: true, owner: role === 'owner' });
      return res.json({ ok: true });
    }

    // Manager-only: which role codes are currently set.
    if (action === 'role-list') {
      if (!(await callerIsManager(req))) return res.status(403).json({ error: 'Managers only.' });
      const set = [];
      for (const role of Object.keys(ROLE_UIDS)) {
        try { await auth.getUser(ROLE_UIDS[role]); set.push(role); } catch (e) { /* not set */ }
      }
      return res.json({ ok: true, set });
    }

    // Manager-only: remove a role code (ordering app locks again until reset).
    if (action === 'role-clear') {
      if (!(await callerIsManager(req))) return res.status(403).json({ error: 'Managers only.' });
      const role = String(body.role || '');
      if (!ROLE_UIDS[role]) return res.status(400).json({ error: 'Unknown role.' });
      try { await auth.deleteUser(ROLE_UIDS[role]); } catch (e) { /* already gone */ }
      return res.json({ ok: true });
    }

    return res.status(400).json({ error: 'Unknown action.' });
  } catch (e) {
    return res.status(500).json({ error: String((e && e.message) || e) });
  }
};
