# blind-encryption-sodium

Implemention of encryption encoding for Autobase blind encryption using sodium easy box

## Usage

```js
const BlindEncryptionSodium = require('blind-encryption-sodium')
const b4a = require('b4a')

const entropy = b4a.alloc(32) // 32-byte key
// ... fill entropy

const encryption = new BlindEncryptionSodium([{ key: entropy, type: 0 }])

const encrypted = await encryption.encrypt(plaintext)
// { value: <Buffer>, type: 1 }

const decrypted = await encryption.decrypt(encrypted)
```

Multiple values can be passed in. This enables you to "rotate" keys.
* Value encrypted with an old `type` will be upgraded to the latest `type`
* Cannot be downgraded
* Old types are no longer needed after upgrade

### Usage with Autobase:

```js
const base = new Autobase(store, {
  apply,
  open,
  encryptionKey,
  blindEncryption: new BlindEncryptionSodium([
    { key: oldEntropy, type: 0 },
    { key: newEntropy, type: 1 },
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
