const b4a = require('b4a')
const sodium = require('sodium-universal')

class BlindEncryptionSodium {
  constructor(entropy) {
    this._entropy = entropy || null
    this._type = 1

    this.encrypt = async (key) => {
      const buffer = b4a.allocUnsafe(
        key.byteLength + sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES
      )
      const nonce = buffer.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
      const box = buffer.subarray(nonce.byteLength)

      sodium.randombytes_buf(nonce)
      sodium.crypto_secretbox_easy(box, key, nonce, this._entropy)

      return { value: buffer, type: 1 }
    }

    this.decrypt = async ({ value, type }) => {
      if (type !== this._type) {
        throw new Error('Not encrypted using BlindEncryptionSodium')
      }

      const nonce = value.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
      const box = value.subarray(nonce.byteLength)
      const output = b4a.allocUnsafe(box.byteLength - sodium.crypto_secretbox_MACBYTES)

      sodium.crypto_secretbox_open_easy(output, box, nonce, this._entropy)
      return output
    }
  }
}

module.exports = BlindEncryptionSodium
