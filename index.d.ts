declare module 'blind-encryption-sodium' {
  interface EncryptedData {
    value: Buffer
    type: number
  }

  declare class BlindEncryptionSodium {
    constructor(entropy?: Buffer | null)
    encrypt(key: Buffer): Promise<EncryptedData>
    decrypt(data: EncryptedData): Promise<Buffer>
  }

  export = BlindEncryptionSodium
}
