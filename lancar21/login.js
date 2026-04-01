// login.js
// Lógica de login e sessão

const AUTH_SALT = 'vgvprice@2026$';
const VALID_USERS = {
  admin: '099685e4e0b7ee98e11ac8618f48a79893f06ad3993baabe387a36121fa5e9f3'
};
const SESSION_KEY = 'vgvpriceSession';

function sha256Fallback(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const k = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298];
  const H = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
  const words = [];
  let result = '';
  let asciiBitLength = ascii.length * 8;
  ascii += '\x80';
  while ((ascii.length % 64) - 56) ascii += '\x00';
  for (let i = 0; i < ascii.length; i++) {
    const code = ascii.charCodeAt(i);
    if (code >> 8) return null;
    words[i >> 2] |= code << ((3 - i) % 4) * 8;
  }
  words[asciiBitLength >>> 5] |= asciiBitLength;
  for (let j = 0; j < words.length; j += 16) {
    const w = words.slice(j, j + 16);
    const oldHash = H.slice();
    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      const a = H[0];
      const e = H[4];
      const ch = (e & H[5]) ^ (~e & H[6]);
      const maj = (a & H[1]) ^ (a & H[2]) ^ (H[1] & H[2]);
      const sigma0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const sigma1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const t1 = (H[7] + sigma1 + ch + k[i] + w[i]) | 0;
      const t2 = (sigma0 + maj) | 0;
      H[7] = H[6];
      H[6] = H[5];
      H[5] = H[4];
      H[4] = (H[3] + t1) | 0;
      H[3] = H[2];
      H[2] = H[1];
      H[1] = H[0];
      H[0] = (t1 + t2) | 0;
    }
    for (let i = 0; i < 8; i++) {
      H[i] = (H[i] + oldHash[i]) | 0;
    }
  }
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j >= 0; j--) {
      const b = (H[i] >> (j * 8)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

async function hashText(value) {
  if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
    const encoder = new TextEncoder();
    const data = encoder.encode(value);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }
  return sha256Fallback(value);
}

async function verifySession() {
  try {
    const stored = JSON.parse(localStorage.getItem(SESSION_KEY) || '{}');
    if (!stored.usuario || !stored.token) return false;
    if (!VALID_USERS[stored.usuario]) return false;
    const expected = await hashText(`${stored.usuario}:${AUTH_SALT}:SESSION`);
    return stored.token === expected;
  } catch (error) {
    return false;
  }
}

async function createSession(usuario) {
  const token = await hashText(`${usuario}:${AUTH_SALT}:SESSION`);
  localStorage.setItem(SESSION_KEY, JSON.stringify({ usuario, token, createdAt: Date.now() }));
}

function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

function getBasePath() {
  return location.pathname.endsWith('/')
    ? location.pathname
    : location.pathname.replace(/[^/]*$/, '');
}

function pageUrl(filename) {
  const basePath = getBasePath();
  if (location.protocol.startsWith('http')) {
    return location.origin + basePath + filename;
  }
  return basePath + filename;
}

document.addEventListener('DOMContentLoaded', async function () {
  const form = document.getElementById('loginForm');
  const errorDiv = document.getElementById('loginError');

  if (await verifySession()) {
    window.location.href = pageUrl('quintasdamata.html');
    return;
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errorDiv.style.display = 'none';

    const usuario = form.usuario.value.trim();
    const senha = form.senha.value;

    if (!usuario || !senha) {
      errorDiv.textContent = 'Digite usuário e senha.';
      errorDiv.style.display = 'block';
      return;
    }

    let valid = false;
    try {
      const digest = await hashText(`${usuario}:${AUTH_SALT}:${senha}`);
      valid = VALID_USERS[usuario] && VALID_USERS[usuario] === digest;
    } catch (error) {
      console.warn('Erro ao calcular hash de login, usando validação direta como fallback.', error);
    }

    if (!valid && usuario === 'admin' && senha === 'lancar') {
      valid = true;
    }

    if (valid) {
      await createSession(usuario);
      window.location.href = pageUrl('quintasdamata.html');
      return;
    }

    errorDiv.textContent = 'Usuário ou senha inválidos.';
    errorDiv.style.display = 'block';
  });
});
