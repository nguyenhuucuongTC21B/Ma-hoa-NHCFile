const crypto = require('crypto');
const { KeyPair } = require('../models');
const logger = require('../config/logger');

class KMSController {
  // Tạo cặp khóa mới cho user
  static async generateKeyPair(userId, masterPassword) {
    try {
      // Tạo cặp khóa RSA
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: masterPassword
        }
      });

      // Lưu vào database
      const keyPair = await KeyPair.create({
        userId,
        publicKey,
        privateKeyEncrypted: privateKey,
        keyAlgorithm: 'RSA-OAEP',
        keySize: 2048
      });

      return {
        publicKey,
        keyPairId: keyPair.id
      };
    } catch (error) {
      logger.error(`Error generating key pair: ${error.message}`);
      throw error;
    }
  }

  // Lấy khóa công khai
  static async getPublicKey(keyPairId) {
    try {
      const keyPair = await KeyPair.findOne({
        where: { id: keyPairId, isActive: true }
      });
      return keyPair ? keyPair.publicKey : null;
    } catch (error) {
      logger.error(`Error getting public key: ${error.message}`);
      throw error;
    }
  }

  // Giải mã với khóa riêng tư
  static async decryptWithPrivateKey(keyPairId, encryptedData, masterPassword) {
    try {
      const keyPair = await KeyPair.findOne({
        where: { id: keyPairId, isActive: true }
      });

      if (!keyPair) {
        throw new Error('Key pair not found or inactive');
      }

      const decrypt = crypto.createPrivateKey({
        key: keyPair.privateKeyEncrypted,
        format: 'pem',
        type: 'pkcs8',
        passphrase: masterPassword
      });

      const buffer = Buffer.from(encryptedData, 'base64');
      const decrypted = crypto.privateDecrypt(
        {
          key: decrypt,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        buffer
      );

      return decrypted.toString('utf8');
    } catch (error) {
      logger.error(`Error decrypting with private key: ${error.message}`);
      throw error;
    }
  }
}

module.exports = KMSController;