#!/usr/bin/env node
/**
 * Reset an account's password by hand.
 *
 * There is no e-mail reset flow, so when a user has forgotten their password
 * and has no device left that is still signed in, the only way back in is to
 * write a new hash into the database. This prints one in exactly the format
 * src/worker.js stores (PBKDF2-SHA256, 100k iterations, random 16-byte salt),
 * plus the UPDATE statement to run.
 *
 *   node tools/hash-password.mjs <uus-parool> <e-post>
 *
 * The password never leaves this machine — only its hash goes to the database.
 * Send the new password to the user over a channel they control, and tell them
 * to change it themselves from the app's "Parool" button afterwards.
 */
import { webcrypto as crypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ITERATIONS = 100000;
const b64 = bytes => Buffer.from(bytes).toString('base64');

async function deriveBits(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256
  ));
}

// Same layout as hashPassword() in src/worker.js: pbkdf2$<iters>$<salt>$<hash>.
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITERATIONS}$${b64(salt)}$${b64(await deriveBits(password, salt, ITERATIONS))}`;
}

// Same check as verifyPassword() in src/worker.js — run against our own output
// so a format drift between the two files shows up here rather than at login.
async function verifyPassword(password, stored) {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const salt = new Uint8Array(Buffer.from(parts[2], 'base64'));
  return b64(await deriveBits(password, salt, parseInt(parts[1]))) === parts[3];
}

const [password, email] = process.argv.slice(2);
if (!password || !email) {
  console.error('Kasutus: node tools/hash-password.mjs <uus-parool> <e-post>');
  process.exit(1);
}
if (password.length < 8) {
  console.error('Parool peab olema vähemalt 8 tähemärki (sama piir kui registreerimisel).');
  process.exit(1);
}

const hash = await hashPassword(password);
if (!(await verifyPassword(password, hash))) {
  console.error('Enesekontroll ebaõnnestus — räsi ei vasta paroolile. Ära kasuta seda.');
  process.exit(1);
}

const emailLc = email.toLowerCase().trim().replace(/'/g, "''");
const sql = `UPDATE users SET password_hash = '${hash}' WHERE email = '${emailLc}';`;

// The hash contains '$' and the SQL contains quotes, which a shell would eat if
// this were pasted as --command. Hand wrangler a file instead, so nothing has
// to survive shell quoting.
const sqlPath = join(tmpdir(), `soidupaevik-reset-${Date.now()}.sql`);
writeFileSync(sqlPath, sql + '\n', { mode: 0o600 });

console.log(`\nE-post:  ${emailLc}`);
console.log(`SQL:     ${sqlPath}\n`);
console.log('1) Kontrolli, et konto on olemas:\n');
console.log(`  npx wrangler d1 execute soidupaevik-db --remote --command "SELECT id, email FROM users WHERE email = '${emailLc}';"\n`);
console.log('2) Määra uus parool:\n');
console.log(`  npx wrangler d1 execute soidupaevik-db --remote --file='${sqlPath}'\n`);
console.log('3) Kustuta ajutine fail, kui valmis:\n');
console.log(`  rm '${sqlPath}'\n`);
