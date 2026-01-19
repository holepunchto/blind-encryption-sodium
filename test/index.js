const { test } = require('brittle')
const BlindEncryptionSodium = require('..')
const { encrypt, decrypt } = require('encryption-encoding')
const b4a = require('b4a')

test('works', async (t) => {
  const encryptionKey = b4a.from('hello world', 'utf-8')
  const password = b4a.concat([b4a.from('my great password', 'utf-8')], 32)

  const bes = new BlindEncryptionSodium([{ key: password, type: 0 }])

  const encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
  const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)

  t.is(decrypted.toString('utf-8'), 'hello world')
})

test('rotation', async (t) => {
  const encryptionKey = b4a.from('hello world', 'utf-8')
  const password = b4a.concat([b4a.from('my great password', 'utf-8')], 32)
  const newPassword = b4a.concat([b4a.from('my greater password', 'utf-8')], 32)

  let encryptedAndEncoded

  {
    const bes = new BlindEncryptionSodium([{ key: password, type: 0 }])

    encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.is(decrypted.toString('utf-8'), 'hello world')
  }

  // method missing to rotate
  t.exception(async () => {
    const bes = new BlindEncryptionSodium([{ key: newPassword, type: 1 }])
    await decrypt(encryptedAndEncoded, bes.decrypt)
  }, /Missing type: 0/)

  {
    const bes = new BlindEncryptionSodium([
      { key: password, type: 0 },
      { key: newPassword, type: 1 }
    ])

    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.is(decrypted.toString('utf-8'), 'hello world')

    // upgraded
    encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
  }

  t.exception(async () => {
    const bes = new BlindEncryptionSodium([{ key: password, type: 0 }])
    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.is(decrypted.toString('utf-8'), 'hello world')
  }, /Encrypted using new type: 1/)

  // older version not needed use
  {
    const bes = new BlindEncryptionSodium([{ key: newPassword, type: 1 }])

    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.is(decrypted.toString('utf-8'), 'hello world')

    encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
  }
})
