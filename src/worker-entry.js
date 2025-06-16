// src/worker-entry.js
import argon2 from 'argon2-browser/dist/argon2-bundled.min.js';

const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?'.split('');

/** turn a hex string into a Uint8Array */
function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

/** SHA-512 helper */
async function sha512(str) {
  const buf = new TextEncoder().encode(str);
  const hashBuf = await crypto.subtle.digest('SHA-512', buf);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

self.onmessage = async e => {
  console.log('[Worker] got message →', e.data);
  try {
    const { type, masterPass, user, pin, info, length } = e.data;
    if (!self.isSecureContext) {
      throw new Error('Worker not in secure context');
    }

    // derive a salt from (pass+pin) or (pass+user)
    const saltHex = pin
      ? await sha512(masterPass + pin)
      : await sha512(masterPass + user);
    const saltBytes = hexToBytes(saltHex);

    if (type === 'derive') {
      const { hash: derived } = await argon2.hash({
        pass:    masterPass,
        salt:    saltBytes,
        type:    argon2.ArgonType.Argon2id,
        hashLen: 64,
        time:    3,
        mem:     64 * 1024,
      });
      self.postMessage({ type: 'derived', derived });

    } else if (type === 'generate') {
      const infoBytes = new TextEncoder().encode(info);
      const userBytes = new TextEncoder().encode(user);

      const combinedSalt = new Uint8Array(
        saltBytes.length + userBytes.length + infoBytes.length
      );
      let offset = 0;
      combinedSalt.set(saltBytes, offset);
      offset += saltBytes.length;
      combinedSalt.set(userBytes, offset);
      offset += userBytes.length;
      combinedSalt.set(infoBytes, offset);

      const { hash: derived } = await argon2.hash({
        pass:    masterPass,
        salt:    combinedSalt,
        type:    argon2.ArgonType.Argon2id,
        hashLen: 64,
        time:    3,
        mem:     64 * 1024,
      });

      const seed = derived;
      const key  = await crypto.subtle.importKey(
        'raw', seed, 'HKDF', false, ['deriveBits']
      );

      const N            = CHARSET.length;
      const threshold    = Math.floor(256 / N) * N;
      const acceptRate   = threshold / 256;
      const expectedRaw  = Math.ceil(length / acceptRate);
      const neededBits   = expectedRaw * 8;

      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: combinedSalt, info: infoBytes },
        key,
        neededBits
      );
      const raw = new Uint8Array(bits);

      const pwd = [];
      for (const b of raw) {
        if (b < threshold) {
          pwd.push(CHARSET[b % N]);
          if (pwd.length === length) break;
        }
      }

const password = pwd.join('');

      console.log('[Worker] generated', { info, password });
      self.postMessage({ type: 'generated', info, password });
    }
  } catch (err) {
    self.postMessage({ type: 'error', message: err.message });
  }
};

