const { test } = require('brittle')
const BlindEncryptionSodium = require('..')
const { encrypt, decrypt } = require('encryption-encoding')
const b4a = require('b4a')

test('works', async (t) => {
  const encryptionKey = b4a.alloc(40, 'hello world')
  const password = b4a.alloc(32, 'my great password', 'utf-8')

  const bes = new BlindEncryptionSodium(password)

  const encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
  const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)

  t.alike(decrypted.value, encryptionKey)
  t.is(decrypted.rotated, false)
})

test('rotation', async (t) => {
  const encryptionKey = b4a.alloc(40, 'hello world')
  const password = b4a.alloc(32, 'my great password', 'utf-8')
  const newPassword = b4a.alloc(32, 'my greater password', 'utf-8')

  let encryptedAndEncoded

  {
    const bes = new BlindEncryptionSodium(password)

    encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.alike(decrypted.value, encryptionKey)
    t.is(decrypted.rotated, false)
  }

  // method missing to rotate
  t.exception(async () => {
    const bes = new BlindEncryptionSodium(newPassword)
    await decrypt(encryptedAndEncoded, bes.decrypt)
  }, /failed to rotate/)

  {
    const bes = new BlindEncryptionSodium(newPassword, password)

    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.alike(decrypted.value, encryptionKey)
    t.is(decrypted.rotated, true)

    // upgraded
    encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
  }

  t.exception(async () => {
    const bes = new BlindEncryptionSodium(password)
    await decrypt(encryptedAndEncoded, bes.decrypt)
  }, /failed to rotate/)

  // older version not needed use
  {
    const bes = new BlindEncryptionSodium(newPassword)

    const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt)
    t.alike(decrypted.value, encryptionKey)
    t.is(decrypted.rotated, false)

    encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt)
  }
})

test('bad value', async (t) => {
  const encryptionKey = b4a.alloc(20, 'hello world')
  const password = b4a.alloc(32, 'my great password', 'utf-8')

  const bes = new BlindEncryptionSodium(password)

  await t.exception(() => encrypt(encryptionKey, bes.encrypt), /value too short/)
})

test('bad entropy', async (t) => {
  const encryptionKey = b4a.alloc(40, 'hello world')
  const password = b4a.alloc(20, 'my great password', 'utf-8')

  const bes = new BlindEncryptionSodium(password)

  await t.exception(() => encrypt(encryptionKey, bes.encrypt), /invalid entropy length/)
})

test('bad value type', async (t) => {
  const password = b4a.alloc(32, 'my great password', 'utf-8')
  const bes = new BlindEncryptionSodium(password)

  const expected = new TypeError('value must be a Uint8Array')
  try {
    await encrypt('hello world', bes.encrypt)
    t.fail('did not error')
  } catch (e) {
    t.alike(e, expected)
  }
})
