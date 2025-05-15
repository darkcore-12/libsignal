'use strict';

class ProtocolAddress {
  /**
   * Crea una instancia de ProtocolAddress a partir de una dirección codificada en formato "id.deviceId"
   * @param {string} encodedAddress Dirección codificada, ejemplo: "user123.42"
   * @returns {ProtocolAddress}
   * @throws {Error} Si el formato de la dirección es inválido
   */
  static from(encodedAddress) {
    if (typeof encodedAddress !== 'string' || !encodedAddress.match(/^.+\.\d+$/)) {
      throw new Error('Invalid address encoding');
    }
    const parts = encodedAddress.split('.');
    const id = parts[0];
    const deviceId = Number(parts[1]);
    if (isNaN(deviceId)) {
      throw new Error('Invalid deviceId in address encoding');
    }
    return new this(id, deviceId);
  }

  /**
   * Constructor de ProtocolAddress
   * @param {string} id Identificador base (sin puntos)
   * @param {number} deviceId Identificador numérico del dispositivo
   */
  constructor(id, deviceId) {
    if (typeof id !== 'string') {
      throw new TypeError('id required for addr and must be a string');
    }
    if (id.includes('.')) {
      throw new TypeError('encoded addr detected in id, dots are not allowed');
    }
    this.id = id;

    if (typeof deviceId !== 'number' || !Number.isInteger(deviceId)) {
      throw new TypeError('deviceId must be an integer number');
    }
    this.deviceId = deviceId;
  }

  /**
   * Retorna la representación en string de la dirección: "id.deviceId"
   * @returns {string}
   */
  toString() {
    return `${this.id}.${this.deviceId}`;
  }

  /**
   * Compara esta instancia con otra para verificar igualdad
   * @param {ProtocolAddress} other Otra instancia a comparar
   * @returns {boolean} true si ambas direcciones son iguales
   */
  is(other) {
    if (!(other instanceof ProtocolAddress)) {
      return false;
    }
    return other.id === this.id && other.deviceId === this.deviceId;
  }
}

module.exports = ProtocolAddress;
