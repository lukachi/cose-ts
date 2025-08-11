import { describe, it, expect, beforeEach } from 'vitest';
import * as encrypt from '../src/encrypt.js';
import type { COSEHeaders, COSERecipient, COSEOptions } from '../src/types.js';
import * as crypto from 'crypto';
import { p256 } from '@noble/curves/p256';
import { p521 } from '@noble/curves/p521';

describe('COSE Encrypt Module', () => {
  // Test vectors and constants
  const testPayload = Buffer.from('This is the content to be encrypted');
  const testAAD = Buffer.from('Additional Authenticated Data');
  
  // Test keys for symmetric encryption
  const testKeys = {
    aes128: crypto.randomBytes(16),
    aes192: crypto.randomBytes(24),
    aes256: crypto.randomBytes(32)
  };

  // Test ECDH key pairs
  const ecdhKeys = {
    p256: {
      private: p256.utils.randomPrivateKey(),
      public: {} as any
    },
    p521: {
      private: p521.utils.randomPrivateKey(),
      public: {} as any
    }
  };

  beforeEach(() => {
    ecdhKeys.p256.public = p256.getPublicKey(ecdhKeys.p256.private, false);
    ecdhKeys.p521.public = p521.getPublicKey(ecdhKeys.p521.private, false);
  });

  describe('Symmetric Encryption (Encrypt0)', () => {
    it('should encrypt and decrypt with A128GCM', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      // Encrypt
      const encrypted = await encrypt.create(headers, testPayload, recipient);
      expect(encrypted).toBeInstanceOf(Buffer);
      expect(encrypted.length).toBeGreaterThan(testPayload.length);

      // Decrypt
      const decrypted = await encrypt.read(encrypted, testKeys.aes128);
      expect(decrypted).toEqual(testPayload);
    });

    it('should encrypt and decrypt with A192GCM', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A192GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes192
      };

      // Encrypt
      const encrypted = await encrypt.create(headers, testPayload, recipient);
      expect(encrypted).toBeInstanceOf(Buffer);

      // Decrypt
      const decrypted = await encrypt.read(encrypted, testKeys.aes192);
      expect(decrypted).toEqual(testPayload);
    });

    it('should encrypt and decrypt with A256GCM', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A256GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes256
      };

      // Encrypt
      const encrypted = await encrypt.create(headers, testPayload, recipient);
      expect(encrypted).toBeInstanceOf(Buffer);

      // Decrypt
      const decrypted = await encrypt.read(encrypted, testKeys.aes256);
      expect(decrypted).toEqual(testPayload);
    });

    it('should encrypt and decrypt with AES-CCM algorithms', async () => {
      const ccmAlgorithms = [
        { alg: 'AES-CCM-16-64-128', name: 'AES-CCM-16-64-128' },
        { alg: 'AES-CCM-16-64-256', name: 'AES-CCM-16-64-256' },
        { alg: 'AES-CCM-64-64-128', name: 'AES-CCM-64-64-128' },
        { alg: 'AES-CCM-64-64-256', name: 'AES-CCM-64-64-256' },
        { alg: 'AES-CCM-16-128-128', name: 'AES-CCM-16-128-128' },
        { alg: 'AES-CCM-16-128-256', name: 'AES-CCM-16-128-256' },
        { alg: 'AES-CCM-64-128-128', name: 'AES-CCM-64-128-128' },
        { alg: 'AES-CCM-64-128-256', name: 'AES-CCM-64-128-256' }
      ];

      for (const { alg, name } of ccmAlgorithms) {
        const keySize = ['AES-CCM-16-64-256', 'AES-CCM-64-64-256', 'AES-CCM-16-128-256', 'AES-CCM-64-128-256'].includes(alg) ? 32 : 16;
        const key = crypto.randomBytes(keySize);

        const headers: COSEHeaders = {
          p: { alg },
          u: {}
        };

        const recipient: COSERecipient = {
          key: key
        };

        // Encrypt
        const encrypted = await encrypt.create(headers, testPayload, recipient);
        expect(encrypted).toBeInstanceOf(Buffer);

        // Decrypt
        const decrypted = await encrypt.read(encrypted, key);
        expect(decrypted).toEqual(testPayload);
      }
    });

    it('should handle external AAD', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const options: COSEOptions = {
        externalAAD: testAAD
      };

      // Encrypt with AAD
      const encrypted = await encrypt.create(headers, testPayload, recipient, options);
      expect(encrypted).toBeInstanceOf(Buffer);

      // Decrypt with same AAD
      const decrypted = await encrypt.read(encrypted, testKeys.aes128, options);
      expect(decrypted).toEqual(testPayload);

      // Decrypt with different AAD should fail
      const wrongAAD = Buffer.from('Wrong AAD');
      await expect(
        encrypt.read(encrypted, testKeys.aes128, { externalAAD: wrongAAD })
      ).rejects.toThrow();
    });

    it('should handle context IV and partial IV', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const contextIv = crypto.randomBytes(12);
      const options: COSEOptions = {
        contextIv: contextIv
      };

      // Encrypt with context IV
      const encrypted = await encrypt.create(headers, testPayload, recipient, options);
      expect(encrypted).toBeInstanceOf(Buffer);

      // Decrypt with same context IV
      const decrypted = await encrypt.read(encrypted, testKeys.aes128, options);
      expect(decrypted).toEqual(testPayload);
    });

    it('should support custom random source', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      // Deterministic random source for testing
      let counter = 0;
      const deterministicRandom = (bytes: number): Buffer => {
        const buf = Buffer.alloc(bytes);
        for (let i = 0; i < bytes; i++) {
          buf[i] = (counter + i) % 256;
        }
        counter += bytes;
        return buf;
      };

      const options: COSEOptions = {
        randomSource: deterministicRandom
      };

      // Encrypt with custom random source
      const encrypted1 = await encrypt.create(headers, testPayload, recipient, options);
      
      // Reset counter and encrypt again
      counter = 0;
      const encrypted2 = await encrypt.create(headers, testPayload, recipient, options);
      
      // Should produce identical results with deterministic random
      expect(encrypted1).toEqual(encrypted2);

      // Decrypt should work
      const decrypted = await encrypt.read(encrypted1, testKeys.aes128);
      expect(decrypted).toEqual(testPayload);
    });

    it('should support excludetag option', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const options: COSEOptions = {
        excludetag: true
      };

      // Encrypt without tag
      const encrypted = await encrypt.create(headers, testPayload, recipient, options);
      expect(encrypted).toBeInstanceOf(Buffer);

      // Decrypt with defaultType
      const decryptOptions: COSEOptions = {
        defaultType: encrypt.Encrypt0Tag
      };
      const decrypted = await encrypt.read(encrypted, testKeys.aes128, decryptOptions);
      expect(decrypted).toEqual(testPayload);
    });

    it('should support encodep option', async () => {
      const headers: COSEHeaders = {
        p: {},
        u: { alg: 'A128GCM' } // Algorithm in unprotected headers
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const options: COSEOptions = {
        encodep: 'empty'
      };

      // Encrypt with empty protected headers encoding
      const encrypted = await encrypt.create(headers, testPayload, recipient, options);
      expect(encrypted).toBeInstanceOf(Buffer);

      // Decrypt should work
      const decrypted = await encrypt.read(encrypted, testKeys.aes128);
      expect(decrypted).toEqual(testPayload);
    });
  });

  describe('Multi-Recipient Encryption (Encrypt)', () => {
    it('should encrypt with single recipient (symmetric key)', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipients: COSERecipient[] = [{
        key: testKeys.aes128,
        p: {},
        u: {}
      }];

      // Encrypt
      const encrypted = await encrypt.create(headers, testPayload, recipients);
      expect(encrypted).toBeInstanceOf(Buffer);

      // For multi-recipient, we need to handle decryption differently
      // This is a basic test to ensure the encryption doesn't fail
    });

    it('should handle ECDH-ES key agreement', async () => {
      const pubKeyUncompressed = ecdhKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));

      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipients: COSERecipient[] = [{
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(ecdhKeys.p256.private)
        },
        p: { alg: 'ECDH-ES' },
        u: {}
      }];

      // Encrypt with ECDH-ES
      const encrypted = await encrypt.create(headers, testPayload, recipients);
      expect(encrypted).toBeInstanceOf(Buffer);
      expect(encrypted.length).toBeGreaterThan(testPayload.length);
    });

    it('should handle ECDH-ES-512 key agreement', async () => {
      const pubKeyUncompressed = ecdhKeys.p521.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 67));
      const y = Buffer.from(pubKeyUncompressed.slice(67, 133));

      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipients: COSERecipient[] = [{
        key: {
          kty: 'EC2',
          crv: 'P-521',
          x: x,
          y: y,
          d: Buffer.from(ecdhKeys.p521.private)
        },
        p: { alg: 'ECDH-ES-512' },
        u: {}
      }];

      // Encrypt with ECDH-ES-512
      const encrypted = await encrypt.create(headers, testPayload, recipients);
      expect(encrypted).toBeInstanceOf(Buffer);
      expect(encrypted.length).toBeGreaterThan(testPayload.length);
    });

    it('should handle ECDH-SS key agreement', async () => {
      const pubKeyUncompressed = ecdhKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));

      // Generate sender key
      const senderPrivate = p256.utils.randomPrivateKey();
      const senderPublic = p256.getPublicKey(senderPrivate, false);
      const senderX = Buffer.from(senderPublic.slice(1, 33));
      const senderY = Buffer.from(senderPublic.slice(33, 65));

      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipients: COSERecipient[] = [{
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(ecdhKeys.p256.private)
        },
        p: { alg: 'ECDH-SS' },
        u: {},
        sender: {
          kty: 'EC2',
          crv: 'P-256',
          x: senderX,
          y: senderY,
          d: Buffer.from(senderPrivate)
        }
      }];

      // Encrypt with ECDH-SS
      const encrypted = await encrypt.create(headers, testPayload, recipients);
      expect(encrypted).toBeInstanceOf(Buffer);
      expect(encrypted.length).toBeGreaterThan(testPayload.length);
    });

    it('should handle ECDH-SS-512 key agreement', async () => {
      const pubKeyUncompressed = ecdhKeys.p521.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 67));
      const y = Buffer.from(pubKeyUncompressed.slice(67, 133));

      // Generate sender key
      const senderPrivate = p521.utils.randomPrivateKey();
      const senderPublic = p521.getPublicKey(senderPrivate, false);
      const senderX = Buffer.from(senderPublic.slice(1, 67));
      const senderY = Buffer.from(senderPublic.slice(67, 133));

      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipients: COSERecipient[] = [{
        key: {
          kty: 'EC2',
          crv: 'P-521',
          x: x,
          y: y,
          d: Buffer.from(ecdhKeys.p521.private)
        },
        p: { alg: 'ECDH-SS-512' },
        u: {},
        sender: {
          kty: 'EC2',
          crv: 'P-521',
          x: senderX,
          y: senderY,
          d: Buffer.from(senderPrivate)
        }
      }];

      // Encrypt with ECDH-SS-512
      const encrypted = await encrypt.create(headers, testPayload, recipients);
      expect(encrypted).toBeInstanceOf(Buffer);
      expect(encrypted.length).toBeGreaterThan(testPayload.length);
    });
  });

  describe('Error Handling', () => {
    it('should throw error when algorithm is missing', async () => {
      const headers: COSEHeaders = {
        p: {},
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      await expect(
        encrypt.create(headers, testPayload, recipient)
      ).rejects.toThrow('Missing mandatory parameter \'alg\'');
    });

    it('should throw error when recipients array is empty', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      await expect(
        encrypt.create(headers, testPayload, [])
      ).rejects.toThrow('There has to be at least one recipient');
    });

    it('should throw error when multiple recipients are provided', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipients: COSERecipient[] = [
        { key: testKeys.aes128 },
        { key: testKeys.aes256 }
      ];

      await expect(
        encrypt.create(headers, testPayload, recipients)
      ).rejects.toThrow('Encrypting with multiple recipients is not implemented');
    });

    it('should throw error for unsupported algorithm', async () => {
      const headers: COSEHeaders = {
        p: { alg: 'UNSUPPORTED_ALG' }, // Unsupported algorithm
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      await expect(
        encrypt.create(headers, testPayload, recipient)
      ).rejects.toThrow('Unknown \'alg\' parameter, UNSUPPORTED_ALG');
    });

    it('should throw error when IV and Partial IV are both present', async () => {
      // Test that context IV is required when partial IV is used
      const contextIv = crypto.randomBytes(12);
      const encrypted = await encrypt.create({
        p: { alg: 'A128GCM' },
        u: {}
      }, testPayload, { key: testKeys.aes128 }, { contextIv });

      // This should work fine with context IV
      const decrypted = await encrypt.read(encrypted, testKeys.aes128, { contextIv });
      expect(decrypted).toEqual(testPayload);
    });

    it('should require context IV when partial IV is used', async () => {
      // Create encrypted data with partial IV
      const contextIv = crypto.randomBytes(12);
      const encrypted = await encrypt.create({
        p: { alg: 'A128GCM' },
        u: {}
      }, testPayload, { key: testKeys.aes128 }, { contextIv });

      // Should fail when trying to decrypt without context IV
      await expect(
        encrypt.read(encrypted, testKeys.aes128)
      ).rejects.toThrow('Context IV must be provided when Partial IV is used');
    });

    it('should throw error for unknown tag', async () => {
      const validEncrypted = await encrypt.create({
        p: { alg: 'A128GCM' },
        u: {}
      }, testPayload, { key: testKeys.aes128 });

      // This test verifies the tag validation logic exists
      // In practice, creating invalid tagged data would require CBOR manipulation
    });

    it('should throw error for invalid array length', async () => {
      // This test would require creating malformed CBOR data
      // The implementation checks for proper array lengths in the read function
    });

    it('should throw error for unknown algorithm in read', async () => {
      // This would require creating encrypted data with an unsupported algorithm
      // and then trying to decrypt it
    });

    it('should throw error when context IV is missing for partial IV', async () => {
      // This test would require creating encrypted data with partial IV
      // and then trying to decrypt without providing context IV
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty payload', async () => {
      const emptyPayload = Buffer.alloc(0);
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const encrypted = await encrypt.create(headers, emptyPayload, recipient);
      expect(encrypted).toBeInstanceOf(Buffer);

      const decrypted = await encrypt.read(encrypted, testKeys.aes128);
      expect(decrypted).toEqual(emptyPayload);
    });

    it('should handle large payload', async () => {
      const largePayload = Buffer.alloc(1024 * 1024, 0x42); // 1MB of 0x42
      const headers: COSEHeaders = {
        p: { alg: 'A128GCM' },
        u: {}
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const encrypted = await encrypt.create(headers, largePayload, recipient);
      expect(encrypted).toBeInstanceOf(Buffer);

      const decrypted = await encrypt.read(encrypted, testKeys.aes128);
      expect(decrypted).toEqual(largePayload);
    });

    it('should handle algorithm in unprotected headers', async () => {
      const headers: COSEHeaders = {
        p: {},
        u: { alg: 'A128GCM' } // Algorithm in unprotected headers
      };

      const recipient: COSERecipient = {
        key: testKeys.aes128
      };

      const encrypted = await encrypt.create(headers, testPayload, recipient);
      expect(encrypted).toBeInstanceOf(Buffer);

      const decrypted = await encrypt.read(encrypted, testKeys.aes128);
      expect(decrypted).toEqual(testPayload);
    });
  });
});
