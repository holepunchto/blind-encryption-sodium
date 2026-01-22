const b4a = require('b4a')
const sodium = require('sodium-universal')

class BlindEncryptionSodium {
  constructor(entropy, oldEntropy) {
    this.encrypt = async (value) => {
      const buffer = this._encrypt(value, entropy)

      return { value: buffer, type: 0 }
    }

    this.decrypt = async ({ value }) => {
      const { output, ok } = this._decrypt(value, oldEntropy || entropy)

      if (!ok) {
        throw new Error(`failed to rotate`)
      }

      return { value: output, rotated: !!oldEntropy }
    }
  }

  _encrypt(value, entropy) {
    if (!value || !value.byteLength) throw new TypeError('value must be a Uint8Array')
    if (!entropy || entropy.byteLength !== sodium.crypto_secretbox_KEYBYTES) {
      throw new Error('invalid entropy length')
    }
    if (value.byteLength < 32) {
      throw new Error('value too short')
    }

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
    const output = b4a.alloc(box.byteLength - sodium.crypto_secretbox_MACBYTES)

    const ok = sodium.crypto_secretbox_open_easy(output, box, nonce, entropy)
    return { output, ok }
  }
}

module.exports = BlindEncryptionSodium
