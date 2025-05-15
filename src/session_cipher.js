const ChainType = require('./chain_type');
const ProtocolAddress = require('./protocol_address');
const SessionBuilder = require('./session_builder');
const SessionRecord = require('./session_record');
const crypto = require('./crypto');
const curve = require('./curve');
const errors = require('./errors');
const protobufs = require('./protobufs');
const queueJob = require('./queue_job');

const VERSION = 3;

/**
 * Valida que el valor sea un Buffer, lanza error si no.
 * @param {*} value 
 * @returns {Buffer}
 */
function assertBuffer(value) {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError(`Expected Buffer instead of: ${value?.constructor?.name || typeof value}`);
    }
    return value;
}

class SessionCipher {
    /**
     * Constructor del cifrador de sesión.
     * @param {Object} storage - Objeto para cargar y guardar sesiones e identidad.
     * @param {ProtocolAddress} protocolAddress - Dirección del protocolo usada para identificar la sesión.
     */
    constructor(storage, protocolAddress) {
        if (!(protocolAddress instanceof ProtocolAddress)) {
            throw new TypeError("protocolAddress must be a ProtocolAddress");
        }
        this.addr = protocolAddress;
        this.storage = storage;
    }

    /**
     * Codifica dos números (4 bits cada uno) en un byte.
     * @param {number} number1 - Primer número (4 bits max)
     * @param {number} number2 - Segundo número (4 bits max)
     * @returns {number}
     */
    _encodeTupleByte(number1, number2) {
        if (number1 > 15 || number2 > 15) {
            throw new TypeError("Numbers must be 4 bits or less");
        }
        return (number1 << 4) | number2;
    }

    /**
     * Decodifica un byte en dos números de 4 bits.
     * @param {number} byte 
     * @returns {[number, number]}
     */
    _decodeTupleByte(byte) {
        return [byte >> 4, byte & 0xf];
    }

    toString() {
        return `<SessionCipher(${this.addr.toString()})>`;
    }

    /** Carga el registro de sesión desde el almacenamiento */
    async getRecord() {
        const record = await this.storage.loadSession(this.addr.toString());
        if (record && !(record instanceof SessionRecord)) {
            throw new TypeError('SessionRecord type expected from loadSession'); 
        }
        return record;
    }

    /** Guarda el registro de sesión en el almacenamiento */
    async storeRecord(record) {
        record.removeOldSessions();
        await this.storage.storeSession(this.addr.toString(), record);
    }

    /** Cola una tarea para evitar condiciones de carrera */
    async queueJob(awaitable) {
        return await queueJob(this.addr.toString(), awaitable);
    }

    /**
     * Encripta un mensaje usando la sesión abierta.
     * @param {Buffer} data 
     * @returns {Promise<Object>} Mensaje cifrado y metadata.
     */
    async encrypt(data) {
        assertBuffer(data);
        const ourIdentityKey = await this.storage.getOurIdentity();
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) throw new errors.SessionError("No sessions");

            const session = record.getOpenSession();
            if (!session) throw new errors.SessionError("No open session");

            const remoteIdentityKey = session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }

            const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey);
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }

            this.fillMessageKeys(chain, chain.chainKey.counter + 1);

            const keys = crypto.deriveSecrets(
                chain.messageKeys[chain.chainKey.counter],
                Buffer.alloc(32),
                Buffer.from("WhisperMessageKeys")
            );
            delete chain.messageKeys[chain.chainKey.counter];

            const msg = protobufs.WhisperMessage.create({
                ephemeralKey: session.currentRatchet.ephemeralKeyPair.pubKey,
                counter: chain.chainKey.counter,
                previousCounter: session.currentRatchet.previousCounter,
                ciphertext: crypto.encrypt(keys[0], data, keys[2].slice(0, 16))
            });

            const msgBuf = protobufs.WhisperMessage.encode(msg).finish();

            const macInput = Buffer.concat([
                ourIdentityKey.pubKey,
                remoteIdentityKey,
                Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
                msgBuf
            ]);

            const mac = crypto.calculateMAC(keys[1], macInput);
            const result = Buffer.concat([
                Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
                msgBuf,
                mac.slice(0, 8)
            ]);

            await this.storeRecord(record);

            if (session.pendingPreKey) {
                const preKeyMsg = protobufs.PreKeyWhisperMessage.create({
                    identityKey: ourIdentityKey.pubKey,
                    registrationId: await this.storage.getOurRegistrationId(),
                    baseKey: session.pendingPreKey.baseKey,
                    signedPreKeyId: session.pendingPreKey.signedKeyId,
                    message: result,
                    preKeyId: session.pendingPreKey.preKeyId || undefined
                });

                const body = Buffer.concat([
                    Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
                    protobufs.PreKeyWhisperMessage.encode(preKeyMsg).finish()
                ]);

                return { type: 3, body, registrationId: session.registrationId };
            }

            return { type: 1, body: result, registrationId: session.registrationId };
        });
    }

    /**
     * Intenta desencriptar con varias sesiones.
     * @param {Buffer} data 
     * @param {Session[]} sessions 
     * @returns {Promise<{session: Session, plaintext: Buffer}>}
     */
    async decryptWithSessions(data, sessions) {
        if (!sessions.length) throw new errors.SessionError("No sessions available");
        const errs = [];
        for (const session of sessions) {
            try {
                const plaintext = await this.doDecryptWhisperMessage(data, session);
                session.indexInfo.used = Date.now();
                return { session, plaintext };
            } catch (e) {
                errs.push(e);
            }
        }
        throw new errors.SessionError("No matching sessions found for message");
    }

    /**
     * Desencripta un mensaje Whisper estándar.
     * @param {Buffer} data 
     * @returns {Promise<Buffer>}
     */
    async decryptWhisperMessage(data) {
        assertBuffer(data);
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (!record) throw new errors.SessionError("No session record");

            const result = await this.decryptWithSessions(data, record.getSessions());

            const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey;
            if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
                throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
            }

            // Se podría manejar cierre de sesión aquí, si necesario.
            if (record.isClosed(result.session)) {}

            await this.storeRecord(record);
            return result.plaintext;
        });
    }

    /**
     * Desencripta un mensaje PreKey Whisper.
     * @param {Buffer} data 
     * @returns {Promise<Buffer>}
     */
    async decryptPreKeyWhisperMessage(data) {
        assertBuffer(data);
        const versions = this._decodeTupleByte(data[0]);
        if (versions[1] > VERSION || versions[0] < VERSION) {
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }
        return await this.queueJob(async () => {
            let record = await this.getRecord();
            const preKeyProto = protobufs.PreKeyWhisperMessage.decode(data.slice(1));
            if (!record) {
                if (preKeyProto.registrationId == null) {
                    throw new Error("No registrationId");
                }
                record = new SessionRecord();
            }

            const builder = new SessionBuilder(this.storage, this.addr);
            const preKeyId = await builder.initIncoming(record, preKeyProto);
            const session = record.getSession(preKeyProto.baseKey);
            const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session);
            await this.storeRecord(record);
            if (preKeyId) await this.storage.removePreKey(preKeyId);
            return plaintext;
        });
    }

    /**
     * Desencripta un mensaje Whisper con una sesión específica.
     * @param {Buffer} messageBuffer 
     * @param {Session} session 
     * @returns {Promise<Buffer>}
     */
    async doDecryptWhisperMessage(messageBuffer, session) {
        assertBuffer(messageBuffer);
        if (!session) throw new TypeError("session required");

        const versions = this._decodeTupleByte(messageBuffer[0]);
        if (versions[1] > VERSION || versions[0] < VERSION) {
            throw new Error("Incompatible version number on WhisperMessage");
        }

        const messageProto = messageBuffer.slice(1, -8);
        const message = protobufs.WhisperMessage.decode(messageProto);

        this.maybeStepRatchet(session, message.ephemeralKey, message.previousCounter);
        const chain = session.getChain(message.ephemeralKey);

        if (chain.chainType === ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }

        this.fillMessageKeys(chain, message.counter);
        if (!Object.prototype.hasOwnProperty.call(chain.messageKeys, message.counter)) {
            throw new errors.MessageCounterError('Key used already or never filled');
        }

        const messageKey = chain.messageKeys[message.counter];
        delete chain.messageKeys[message.counter];

        const keys = crypto.deriveSecrets(messageKey, Buffer.alloc(32), Buffer.from("WhisperMessageKeys"));
        const ourIdentityKey = await this.storage.getOurIdentity();
        const macInput = Buffer.concat([
            session.indexInfo.remoteIdentityKey,
            ourIdentityKey.pubKey,
            Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
            messageProto
        ]);

        crypto.verifyMAC(macInput, keys[1], messageBuffer.slice(-8), 8);
        const plaintext = crypto.decrypt(keys[0], message.ciphertext, keys[2].slice(0, 16));
        delete session.pendingPreKey;
        return plaintext;
    }

    /**
     * Llena las claves de mensajes desde la posición actual hasta 'counter'.
     * @param {Chain} chain 
     * @param {number} counter 
     */
    fillMessageKeys(chain, counter) {
        if (chain.chainKey.counter >= counter) return;
        if (counter - chain.chainKey.counter > 2000) {
            throw new errors.SessionError('Over 2000 messages into the future!');
        }
        if (!chain.chainKey.key) throw new errors.SessionError('Chain closed');

        const key = chain.chainKey.key;
        chain.messageKeys[chain.chainKey.counter + 1] = crypto.calculateMAC(key, Buffer.from([1]));
        chain.chainKey.key = crypto.calculateMAC(key, Buffer.from([2]));
        chain.chainKey.counter += 1;

        return this.fillMessageKeys(chain, counter);
    }

    /**
     * Posiblemente avanza el ratchet de sesión ante una nueva clave remota.
     * @param {Session} session 
     * @param {Buffer} remoteKey 
     * @param {number} previousCounter 
     */
    maybeStepRatchet(session, remoteKey, previousCounter) {
        if (session.getChain(remoteKey)) return;

        const ratchet = session.currentRatchet;
        const previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey);

        if (previousRatchet) {
            this.fillMessageKeys(previousRatchet, previousCounter);
            delete previousRatchet.chainKey.key;
        }

        this.calculateRatchet(session, remoteKey, false);

        const prevCounter = session.getChain(ratchet.ephemeralKeyPair.pubKey);
        if (prevCounter) {
            ratchet.previousCounter = prevCounter.chainKey.counter;
            session.deleteChain(ratchet.ephemeralKeyPair.pubKey);
        }

        ratchet.ephemeralKeyPair = curve.generateKeyPair();
        this.calculateRatchet(session, remoteKey, true);
        ratchet.lastRemoteEphemeralKey = remoteKey;
    }

    /**
     * Calcula y añade una nueva cadena ratchet para la sesión.
     * @param {Session} session 
     * @param {Buffer} remoteKey 
     * @param {boolean} sending 
     */
    calculateRatchet(session, remoteKey, sending) {
        const ratchet = session.currentRatchet;
        const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
        const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, Buffer.from("WhisperRatchet"), 2);

        const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;

        session.addChain(chainKey, {
            messageKeys: {},
            chainKey: {
                counter: -1,
                key: masterKey[1]
            },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
        });

        ratchet.rootKey = masterKey[0];
    }

    /** Devuelve si existe una sesión abierta */
    async hasOpenSession() {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            return record?.haveOpenSession() || false;
        });
    }

    /** Cierra la sesión abierta si existe */
    async closeOpenSession() {
        return await this.queueJob(async () => {
            const record = await this.getRecord();
            if (record) {
                const openSession = record.getOpenSession();
                if (openSession) {
                    record.closeSession(openSession);
                    await this.storeRecord(record);
                }
            }
        });
    }
}

module.exports = SessionCipher;
