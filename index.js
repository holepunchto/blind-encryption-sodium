const b4a = require('b4a')
const sodium = require('sodium-universal')

class BlindEncryptionSodium {
  constructor(entropies) {
    this._entropies = entropies.sort((a, b) => b.type - a.type)

    this.encrypt = async (value) => {
      // use latest
      const entropy = this._entropies[0]
      const buffer = this._encrypt(value, entropy.key)

      return { value: buffer, type: entropy.type }
    }

    this.decrypt = async ({ value, type }) => {
      const entropy = this._entropies[0]

      // no backward compat
      if (type > entropy.type) throw new Error('Encrypted using new type: ' + type)

      // auto upgrade
      if (type < entropy.type) {
        const usedEntropy = this._entropies.find((e) => e.type === type)
        if (!usedEntropy) throw new Error('Missing type: ' + type)

        const decrypted = this._decrypt(value, usedEntropy.key)

        return decrypted
      }

      return this._decrypt(value, entropy.key)
    }
  }

  _encrypt(value, entropy) {
    const buffer = b4a.allocUnsafe(
      value.byteLength + sodium.crypto_secretbox_MACBYTES + sodium.crypto_secretbox_NONCEBYTES
    )
    const nonce = buffer.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
    const box = buffer.subarray(nonce.byteLength)

    sodium.randombytes_buf(nonce)
    sodium.crypto_secretbox_easy(box, value, nonce, entropy)

    return buffer
  }

  _decrypt(value, entropy) {
    const nonce = value.subarray(0, sodium.crypto_secretbox_NONCEBYTES)
    const box = value.subarray(nonce.byteLength)
    const output = b4a.allocUnsafe(box.byteLength - sodium.crypto_secretbox_MACBYTES)

    sodium.crypto_secretbox_open_easy(output, box, nonce, entropy)
    return output
  }
}

module.exports = BlindEncryptionSodium
