const b4a = require('b4a')
const sodium = require('sodium-universal')
const isZero = require('is-zero-buffer')

class BlindEncryptionSodium {
  constructor(entropies) {
    this._entropies = entropies

    this.encrypt = async (value) => {
      // use latest
      const entropy = this._entropies[this._entropies.length - 1]
      const buffer = this._encrypt(value, entropy.key)

      return { value: buffer, type: 0 }
    }

    this.decrypt = async ({ value }) => {
      let decrypted
      let rotated = false

      for (let i = 0; i < this._entropies.length; i++) {
        const res = this._decrypt(value, this._entropies[i].key)
        if (isZero(res)) continue
        decrypted = res
        rotated = !b4a.equals(
          this._entropies[i].key,
          this._entropies[this._entropies.length - 1].key
        )
      }

      if (!decrypted) {
        throw new Error('key missing')
      }

      return { value: decrypted, rotated }
    }
  }

  _encrypt(value, entropy) {
    if (!value || !value.byteLength) throw new TypeError('value must be a Uint8Array')
    if (!entropy || entropy.byteLength !== sodium.crypto_secretbox_KEYBYTES) {
      throw new Error('invalid key length')
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

    sodium.crypto_secretbox_open_easy(output, box, nonce, entropy)
    return output
  }
}

module.exports = BlindEncryptionSodium
