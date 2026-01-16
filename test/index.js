const { test } = require('brittle')
const BlindEncryptionSodium = require('..')
const { encrypt, decrypt } = require('encryption-encoding')
const b4a = require('b4a')

test('works', async (t) => {
  const encryptionKey = b4a.from('hello world', 'utf-8')
  const password = b4a.concat([b4a.from('my great password', 'utf-8')], 32)

  const bes = new BlindEncryptionSodium(password)

  const encryptedAndEncoded = await encrypt(encryptionKey, bes.encrypt.bind(bes))
  const decrypted = await decrypt(encryptedAndEncoded, bes.decrypt.bind(bes))

  t.is(decrypted.toString('utf-8'), 'hello world')
})
