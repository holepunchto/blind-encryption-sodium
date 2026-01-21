# blind-encryption-sodium

Implemention of encryption encoding for Autobase blind encryption using sodium easy box

## Usage

```js
const BlindEncryptionSodium = require('blind-encryption-sodium')
const b4a = require('b4a')

const key = b4a.alloc(32) // 32-byte key

const encryption = new BlindEncryptionSodium([{ key, type: 0 }])

const encrypted = await encryption.encrypt(plaintext)
// { value: <Buffer>, type: 1 }

const { value, rotated } = await encryption.decrypt(encrypted)

// if rotated, it was decrypted with a newer type, and you should encrypt and store
```

Multiple values can be passed in. This enables you to "rotate" keys.

- Value encrypted with an old `type` will be upgraded to the latest `type`
- Cannot be downgraded
- Old types are no longer needed after upgrade
- Returns if rotated when decrypting. Note: if it was decrypted with a newer type, you should encrypt and store to ensure it uses your latest key/entropy

### Usage with Autobase:

```js
const base = new Autobase(store, {
  apply,
  open,
  encryptionKey,
  blindEncryption: new BlindEncryptionSodium([
    { key: oldKey, type: 0 },
    { key: newKey, type: 1 }
  ])
})
```

### Usage with encryption-encoding

Internally, Autobase uses this with encryption-encoding

```js
const { encrypt, decrypt } = require('encryption-encoding')
const BlindEncryptionSodium = require('blind-encryption-sodium')

const encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt.bind(bes))
const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt.bind(bes))
```

## License

Apache-2.0
