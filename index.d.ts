declare module 'blind-encryption-sodium' {
  interface EncryptedData {
    value: Buffer
    type: number
  }

  declare class BlindEncryptionSodium {
    constructor(entropy: Buffer, oldEntropy?: Buffer)
    encrypt(key: Buffer): Promise<EncryptedData>
    decrypt(data: EncryptedData): Promise<Buffer>
  }

  export = BlindEncryptionSodium
}
