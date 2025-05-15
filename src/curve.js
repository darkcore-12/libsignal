'use strict';

const curveJs = require('curve25519-js');
const nodeCrypto = require('crypto');

// Prefijos DER para claves
const PUBLIC_KEY_DER_PREFIX = Buffer.from([48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0]);
const PRIVATE_KEY_DER_PREFIX = Buffer.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32]);

const KEY_BUNDLE_TYPE = Buffer.from([5]);

// 🔧 Función auxiliar para validar buffers
function isValidBuffer(buf, length) {
    return Buffer.isBuffer(buf) && buf.length === length;
}

// 🔒 Agrega prefijo para clave pública
function prefixKeyInPublicKey(pubKey) {
    return Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
}

// ✅ Validación robusta de clave privada
function validatePrivKey(privKey) {
    if (!isValidBuffer(privKey, 32)) {
        throw new Error("Private key must be a 32-byte Buffer");
    }
}

// ✅ Validación y normalización de clave pública
function scrubPubKeyFormat(pubKey) {
    if (!Buffer.isBuffer(pubKey)) {
        throw new Error("Public key must be a Buffer");
    }

    if (pubKey.byteLength === 33 && pubKey[0] === 5) {
        return pubKey.slice(1);
    } else if (pubKey.byteLength === 32) {
        console.warn("WARNING: Expected pubkey of length 33, please verify client");
        return pubKey;
    } else {
        throw new Error("Invalid public key format");
    }
}

// 🔁 Reversión del clamping Ed25519
function unclampEd25519PrivateKey(clampedSk) {
    const unclampedSk = new Uint8Array(clampedSk);
    unclampedSk[0] |= 6;
    unclampedSk[31] |= 128;
    unclampedSk[31] &= ~64;
    return unclampedSk;
}

// 📤 Obtener clave pública desde privada
exports.getPublicFromPrivateKey = function(privKey) {
    validatePrivKey(privKey);
    const unclampedPK = unclampEd25519PrivateKey(privKey);
    const keyPair = curveJs.generateKeyPair(unclampedPK);
    return prefixKeyInPublicKey(Buffer.from(keyPair.public));
};

// 🔑 Generar par de claves
exports.generateKeyPair = function () {
    try {
        const keyPair = nodeCrypto.generateKeyPairSync('x25519', {
            publicKeyEncoding: { format: 'der', type: 'spki' },
            privateKeyEncoding: { format: 'der', type: 'pkcs8' }
        });

        const pubKey = keyPair.publicKey.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32);
        const privKey = keyPair.privateKey.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);

        if (!isValidBuffer(pubKey, 32) || !isValidBuffer(privKey, 32)) {
            throw new Error("Generated keys are invalid");
        }

        return {
            pubKey: prefixKeyInPublicKey(pubKey),
            privKey
        };
    } catch (e) {
        console.warn("[Crypto] Native x25519 fallback to curve25519-js:", e.message);
        const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
        return {
            privKey: Buffer.from(keyPair.private),
            pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public))
        };
    }
};

// 🤝 Calcular acuerdo secreto
exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);

    try {
        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });

        return nodeCrypto.diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey
        });
    } catch (e) {
        console.warn("[Crypto] Falling back to curveJs sharedKey:", e.message);
        const secret = curveJs.sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
};

// ✍️ Calcular firma
exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!Buffer.isBuffer(message)) {
        message = Buffer.from(message);
    }
    return Buffer.from(curveJs.sign(privKey, message));
};

// ✅ Verificar firma
exports.verifySignature = function(pubKey, msg, sig) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!isValidBuffer(pubKey, 32)) throw new Error("Invalid public key");
    if (!isValidBuffer(sig, 64)) throw new Error("Invalid signature");

    if (!Buffer.isBuffer(msg)) {
        msg = Buffer.from(msg);
    }

    return curveJs.verify(pubKey, msg, sig);
};

'use strict';

const curveJs = require('curve25519-js');
const nodeCrypto = require('crypto');
// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
  
const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

const KEY_BUNDLE_TYPE = Buffer.from([5]);

const prefixKeyInPublicKey = function (pubKey) {
  return Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
};

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}

function unclampEd25519PrivateKey(clampedSk) {
    const unclampedSk = new Uint8Array(clampedSk);

    // Fix the first byte
    unclampedSk[0] |= 6; // Ensure last 3 bits match expected `110` pattern

    // Fix the last byte
    unclampedSk[31] |= 128; // Restore the highest bit
    unclampedSk[31] &= ~64; // Clear the second-highest bit

    return unclampedSk;
}

exports.getPublicFromPrivateKey = function(privKey) {
    const unclampedPK = unclampEd25519PrivateKey(privKey)
    const keyPair = curveJs.generateKeyPair(unclampedPK);
    return prefixKeyInPublicKey(Buffer.from(keyPair.public))
}

exports.generateKeyPair = function() {
    try {
        const {publicKey: publicDerBytes, privateKey: privateDerBytes} = nodeCrypto.generateKeyPairSync(
            'x25519',
            {
                publicKeyEncoding: { format: 'der', type: 'spki' },
                privateKeyEncoding: { format: 'der', type: 'pkcs8' }
            }
        );
        const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32);
    
        const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);
    
        return {
            pubKey: prefixKeyInPublicKey(pubKey),
            privKey
        };
    } catch(e) {
        const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
        return {
            privKey: Buffer.from(keyPair.private),
            pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public)),
        };
    }
};

exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }

    if(typeof nodeCrypto.diffieHellman === 'function') {
        const nodePrivateKey = nodeCrypto.createPrivateKey({
            key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
            format: 'der',
            type: 'pkcs8'
        });
        const nodePublicKey = nodeCrypto.createPublicKey({
            key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
            format: 'der',
            type: 'spki'
        });
        
        return nodeCrypto.diffieHellman({
            privateKey: nodePrivateKey,
            publicKey: nodePublicKey,
        });
    } else {
        const secret = curveJs.sharedKey(privKey, pubKey);
        return Buffer.from(secret);
    }
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return Buffer.from(curveJs.sign(privKey, message));
};

exports.verifySignature = function(pubKey, msg, sig) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return curveJs.verify(pubKey, msg, sig);
};
