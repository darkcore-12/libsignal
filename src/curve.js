'use strict';
const curveJs = require('curve25519-js');
const nodeCrypto = require('crypto');

// DER Prefixes para claves públicas y privadas
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);

const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

const KEY_BUNDLE_TYPE = Buffer.from([5]);

const prefixKeyInPublicKey = function(pubKey) {
    return Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
};

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength !== 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength !== 33 || pubKey[0] !== 5) && pubKey.byteLength !== 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength === 33) {
        return pubKey.slice(1);
    } else {
        console.warn("WARNING: Expected pubkey of length 33, received length 32. Please report the source.");
        return pubKey;
    }
}

function unclampEd25519PrivateKey(clampedSk) {
    const unclampedSk = new Uint8Array(clampedSk);

    // Ajustes para el formato correcto
    unclampedSk[0] |= 6;      // Ajustar bits iniciales
    unclampedSk[31] |= 128;   // Restaurar bit más alto
    unclampedSk[31] &= ~64;   // Borrar segundo bit más alto

    return unclampedSk;
}

exports.getPublicFromPrivateKey = function(privKey) {
    const unclampedPK = unclampEd25519PrivateKey(privKey);
    const keyPair = curveJs.generateKeyPair(unclampedPK);
    return prefixKeyInPublicKey(Buffer.from(keyPair.public));
}

exports.generateKeyPair = function() {
    if (typeof nodeCrypto.generateKeyPairSync === 'function') {
        try {
            const { publicKey: publicDerBytes, privateKey: privateDerBytes } = nodeCrypto.generateKeyPairSync(
                'x25519',
                {
                    publicKeyEncoding: { format: 'der', type: 'spki' },
                    privateKeyEncoding: { format: 'der', type: 'pkcs8' }
                }
            );

            // Extraer clave pública y privada de DER
            const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32);
            pubKey[0] = 5; // Fijar byte de versión

            const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);

            return {
                pubKey: prefixKeyInPublicKey(pubKey),
                privKey
            };
        } catch (e) {
            // Si falla, usar fallback con curveJs y crypto.randomBytes
            const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32));
            return {
                privKey: Buffer.from(keyPair.private),
                pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public)),
            };
        }
    } else {
        // Si no existe generateKeyPairSync, fallback directo
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
    if (!pubKey || pubKey.byteLength !== 32) {
        throw new Error("Invalid public key");
    }
    if (typeof nodeCrypto.diffieHellman === 'function') {
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
    if (!pubKey || pubKey.byteLength !== 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength !== 64) {
        throw new Error("Invalid signature");
    }
    return curveJs.verify(pubKey, msg, sig);
};
