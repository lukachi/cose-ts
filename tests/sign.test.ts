import { describe, it, expect, beforeEach } from 'vitest';
import * as sign from '../src/sign.js';
import type { COSEHeaders, COSESigner, COSEVerifier, COSEOptions } from '../src/types.js';
import { p256, p384, p521 } from '@noble/curves/nist';
import * as jsrsasign from 'jsrsasign';

describe('COSE Sign Module', () => {
  // Test key pairs for different curves
  const testKeys = {
    p256: {
      private: p256.utils.randomPrivateKey(),
      public: {} as any
    },
    p384: {
      private: p384.utils.randomPrivateKey(),
      public: {} as any
    },
    p521: {
      private: p521.utils.randomPrivateKey(),
      public: {} as any
    }
  };

  // RSA test key pair
  let rsaKeyPair: { private: any; public: any } = { private: null, public: null };

  // Generate public keys from private keys
  beforeEach(() => {
    testKeys.p256.public = p256.getPublicKey(testKeys.p256.private, false); // false = uncompressed
    testKeys.p384.public = p384.getPublicKey(testKeys.p384.private, false); // false = uncompressed
    testKeys.p521.public = p521.getPublicKey(testKeys.p521.private, false); // false = uncompressed
    
    // Generate RSA key pair for testing
    if (!rsaKeyPair.private) {
      const keyPair = jsrsasign.KEYUTIL.generateKeypair('RSA', 2048);
      rsaKeyPair.private = keyPair.prvKeyObj;
      rsaKeyPair.public = keyPair.pubKeyObj;
    }
  });

  describe('ECDSA Signing and Verification', () => {
    it('should create and verify ES256 signature (Sign1)', async () => {
      const payload = Buffer.from('Hello, COSE ES256!');
      
      // Extract coordinates from public key
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: { alg: 'ES256' },
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);
      expect(signedData.length).toBeGreaterThan(0);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should create and verify ES384 signature (Sign1)', async () => {
      const payload = Buffer.from('Hello, COSE ES384!');
      
      // Extract coordinates from public key (P-384 has 48-byte coordinates)
      const pubKeyUncompressed = testKeys.p384.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 49));
      const y = Buffer.from(pubKeyUncompressed.slice(49, 97));
      
      const headers: COSEHeaders = {
        p: { alg: 'ES384' },
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-384',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p384.private)
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-384',
          x: x,
          y: y
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should create and verify ES512 signature (Sign1)', async () => {
      const payload = Buffer.from('Hello, COSE ES512!');
      
      // Extract coordinates from public key (P-521 has 66-byte coordinates)
      const pubKeyUncompressed = testKeys.p521.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 67));
      const y = Buffer.from(pubKeyUncompressed.slice(67, 133));
      
      const headers: COSEHeaders = {
        p: { alg: 'ES512' },
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-521',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p521.private)
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-521',
          x: x,
          y: y
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should handle multiple signers (Sign)', async () => {
      const payload = Buffer.from('Hello, Multi-signer COSE!');
      
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: {},
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private),
          kid: 'test-key-1'
        },
        p: { alg: 'ES256' },
        u: {}
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          kid: 'test-key-1'
        }
      };

      // Create signature with array of signers
      const signedData = await sign.create(headers, payload, [signer]);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should handle truly multiple signers (Sign)', async () => {
      const payload = Buffer.from('Hello, Multi-signer COSE with multiple keys!');
      
      // First signer with P-256
      const pubKeyUncompressed1 = testKeys.p256.public;
      const x1 = Buffer.from(pubKeyUncompressed1.slice(1, 33));
      const y1 = Buffer.from(pubKeyUncompressed1.slice(33, 65));
      
      // Second signer with P-384
      const pubKeyUncompressed2 = testKeys.p384.public;
      const x2 = Buffer.from(pubKeyUncompressed2.slice(1, 49));
      const y2 = Buffer.from(pubKeyUncompressed2.slice(49, 97));
      
      const headers: COSEHeaders = {
        p: {},
        u: {}
      };

      const signer1: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x1,
          y: y1,
          d: Buffer.from(testKeys.p256.private),
          kid: 'signer-1'
        },
        p: { alg: 'ES256' },
        u: {}
      };

      const signer2: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-384',
          x: x2,
          y: y2,
          d: Buffer.from(testKeys.p384.private),
          kid: 'signer-2'
        },
        p: { alg: 'ES384' },
        u: {}
      };

      // Create signature with array of multiple signers
      const signedData = await sign.create(headers, payload, [signer1, signer2]);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify signature with first signer
      const verifier1: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x1,
          y: y1,
          kid: 'signer-1'
        }
      };
      
      const verifiedPayload1 = sign.verifySync(signedData, verifier1);
      expect(verifiedPayload1).toEqual(payload);

      // Verify signature with second signer
      const verifier2: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-384',
          x: x2,
          y: y2,
          kid: 'signer-2'
        }
      };
      
      const verifiedPayload2 = sign.verifySync(signedData, verifier2);
      expect(verifiedPayload2).toEqual(payload);
    });
  });

  describe('Error Handling', () => {
    it('should throw error for unknown algorithm', () => {
      const payload = Buffer.from('Test payload');
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: { alg: 'UNKNOWN_ALG' },
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        }
      };

      expect(() => sign.create(headers, payload, signer)).toThrow('Unknown \'alg\' parameter, UNKNOWN_ALG');
    });

    it('should throw error for missing algorithm', () => {
      const payload = Buffer.from('Test payload');
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: {},
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        }
      };

      expect(() => sign.create(headers, payload, signer)).toThrow('Unknown algorithm, undefined');
    });

    it('should throw error for empty signers array', () => {
      const payload = Buffer.from('Test payload');
      const headers: COSEHeaders = {
        p: { alg: 'ES256' },
        u: {}
      };

      expect(() => sign.create(headers, payload, [])).toThrow('There has to be at least one signer');
    });

    it('should throw error for invalid signature during verification', () => {
      const payload = Buffer.from('Test payload');
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      // Create a fake signed data with invalid signature
      const invalidSignedData = Buffer.from([0x84, 0x40, 0xa0, 0x4a, 0x54, 0x65, 0x73, 0x74, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x58, 0x40]);
      
      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y
        }
      };

      expect(() => sign.verifySync(invalidSignedData, verifier)).toThrow();
    });
  });

  describe('RSA Support', () => {
    it('should create and verify RS256 signature', async () => {
      const payload = Buffer.from('Test RSA RS256 payload');
      const headers: COSEHeaders = {
        p: { alg: 'RS256' },
        u: {}
      };

      // Convert jsrsasign RSA key to COSE format
      const privateJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.private) as any;
      const publicJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.public) as any;

      const signer: COSESigner = {
        key: {
          kty: 'RSA',
          n: Buffer.from(privateJwk.n!, 'base64url'),
          e: Buffer.from(privateJwk.e!, 'base64url'),
          d: Buffer.from(privateJwk.d!, 'base64url'),
          p: Buffer.from(privateJwk.p!, 'base64url'),
          q: Buffer.from(privateJwk.q!, 'base64url'),
          dp: Buffer.from(privateJwk.dp!, 'base64url'),
          dq: Buffer.from(privateJwk.dq!, 'base64url'),
          qi: Buffer.from(privateJwk.qi!, 'base64url')
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'RSA',
          n: Buffer.from(publicJwk.n!, 'base64url'),
          e: Buffer.from(publicJwk.e!, 'base64url')
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);
      expect(signedData.length).toBeGreaterThan(0);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should create and verify PS256 signature', async () => {
      const payload = Buffer.from('Test PSS PS256 payload');
      const headers: COSEHeaders = {
        p: { alg: 'PS256' },
        u: {}
      };

      // Convert jsrsasign RSA key to COSE format
      const privateJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.private) as any;
      const publicJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.public) as any;

      const signer: COSESigner = {
        key: {
          kty: 'RSA',
          n: Buffer.from(privateJwk.n!, 'base64url'),
          e: Buffer.from(privateJwk.e!, 'base64url'),
          d: Buffer.from(privateJwk.d!, 'base64url'),
          p: Buffer.from(privateJwk.p!, 'base64url'),
          q: Buffer.from(privateJwk.q!, 'base64url'),
          dp: Buffer.from(privateJwk.dp!, 'base64url'),
          dq: Buffer.from(privateJwk.dq!, 'base64url'),
          qi: Buffer.from(privateJwk.qi!, 'base64url')
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'RSA',
          n: Buffer.from(publicJwk.n!, 'base64url'),
          e: Buffer.from(publicJwk.e!, 'base64url')
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);
      expect(signedData.length).toBeGreaterThan(0);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should create and verify RS384 signature', async () => {
      const payload = Buffer.from('Test RS384 payload');
      const headers: COSEHeaders = {
        p: { alg: 'RS384' },
        u: {}
      };

      // Convert jsrsasign RSA key to COSE format
      const privateJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.private) as any;
      const publicJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.public) as any;

      const signer: COSESigner = {
        key: {
          kty: 'RSA',
          n: Buffer.from(privateJwk.n!, 'base64url'),
          e: Buffer.from(privateJwk.e!, 'base64url'),
          d: Buffer.from(privateJwk.d!, 'base64url'),
          p: Buffer.from(privateJwk.p!, 'base64url'),
          q: Buffer.from(privateJwk.q!, 'base64url'),
          dp: Buffer.from(privateJwk.dp!, 'base64url'),
          dq: Buffer.from(privateJwk.dq!, 'base64url'),
          qi: Buffer.from(privateJwk.qi!, 'base64url')
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'RSA',
          n: Buffer.from(publicJwk.n!, 'base64url'),
          e: Buffer.from(publicJwk.e!, 'base64url')
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);
      expect(signedData.length).toBeGreaterThan(0);

      // Verify signature
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should work with async functions for RSA', async () => {
      const payload = Buffer.from('Test async RSA payload');
      const headers: COSEHeaders = {
        p: { alg: 'RS384' },
        u: {}
      };

      const privateJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.private) as any;
      const publicJwk = jsrsasign.KEYUTIL.getJWKFromKey(rsaKeyPair.public) as any;

      const signer: COSESigner = {
        key: {
          kty: 'RSA',
          n: Buffer.from(privateJwk.n!, 'base64url'),
          e: Buffer.from(privateJwk.e!, 'base64url'),
          d: Buffer.from(privateJwk.d!, 'base64url'),
          p: Buffer.from(privateJwk.p!, 'base64url'),
          q: Buffer.from(privateJwk.q!, 'base64url'),
          dp: Buffer.from(privateJwk.dp!, 'base64url'),
          dq: Buffer.from(privateJwk.dq!, 'base64url'),
          qi: Buffer.from(privateJwk.qi!, 'base64url')
        }
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'RSA',
          n: Buffer.from(publicJwk.n!, 'base64url'),
          e: Buffer.from(publicJwk.e!, 'base64url')
        }
      };

      // Create signature
      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify signature using async method
      const verifiedPayload = await sign.verify(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });
  });

  describe('Options and Configuration', () => {
    it('should handle excludetag option', async () => {
      const payload = Buffer.from('Test payload with excludetag');
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: { alg: 'ES256' },
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        }
      };

      const options: COSEOptions = {
        excludetag: true
      };

      const signedData = await sign.create(headers, payload, signer, options);
      expect(signedData).toBeInstanceOf(Buffer);
      
      // Should be able to verify with defaultType option
      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y
        }
      };

      const verifyOptions: COSEOptions = {
        defaultType: sign.Sign1Tag
      };

      const verifiedPayload = sign.verifySync(signedData, verifier, verifyOptions);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should handle encodep option', async () => {
      const payload = Buffer.from('Test payload with encodep');
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: {},
        u: { alg: 'ES256' }
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        }
      };

      const options: COSEOptions = {
        encodep: 'empty'
      };

      const signedData = await sign.create(headers, payload, signer, options);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify the signature
      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y
        }
      };

      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);
    });

    it('should handle external AAD', async () => {
      const payload = Buffer.from('Test payload with AAD');
      const externalAAD = Buffer.from('Additional Authenticated Data');
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const headers: COSEHeaders = {
        p: { alg: 'ES256' },
        u: {}
      };

      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        },
        externalAAD: externalAAD
      };

      const verifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y
        },
        externalAAD: externalAAD
      };

      const signedData = await sign.create(headers, payload, signer);
      expect(signedData).toBeInstanceOf(Buffer);

      // Verify with correct AAD
      const verifiedPayload = sign.verifySync(signedData, verifier);
      expect(verifiedPayload).toEqual(payload);

      // Should fail with wrong AAD
      const wrongVerifier: COSEVerifier = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y
        },
        externalAAD: Buffer.from('Wrong AAD')
      };

      expect(() => sign.verifySync(signedData, wrongVerifier)).toThrow('Signature mismatch');
    });
  });

  describe('Async Functions', () => {
    it('should export doSignAsync function', () => {
      expect(typeof sign.doSignAsync).toBe('function');
    });

    it('should export doVerifyAsync function', () => {
      expect(typeof sign.doVerifyAsync).toBe('function');
    });

    it('should handle ECDSA with doSignAsync', async () => {
      const pubKeyUncompressed = testKeys.p256.public;
      const x = Buffer.from(pubKeyUncompressed.slice(1, 33));
      const y = Buffer.from(pubKeyUncompressed.slice(33, 65));
      
      const signer: COSESigner = {
        key: {
          kty: 'EC2',
          crv: 'P-256',
          x: x,
          y: y,
          d: Buffer.from(testKeys.p256.private)
        }
      };

      const sigStructure = ['Signature1', Buffer.alloc(0), Buffer.alloc(0), Buffer.from('test')];
      const alg = -7; // ES256

      const signature = await sign.doSignAsync(sigStructure, signer, alg);
      expect(signature).toBeInstanceOf(Buffer);
      expect(signature.length).toBe(64); // 32 bytes for r + 32 bytes for s
    });
  });

  describe('Tag Constants', () => {
    it('should export correct tag constants', () => {
      expect(sign.SignTag).toBe(98);
      expect(sign.Sign1Tag).toBe(18);
    });
  });

  describe('Integration Tests', () => {
    it('should handle round-trip signing and verification with different algorithms', async () => {
      const payload = Buffer.from('Integration test payload');
      const algorithms = [
        { alg: 'ES256', curve: 'P-256', keyPair: testKeys.p256, coordSize: 32 },
        { alg: 'ES384', curve: 'P-384', keyPair: testKeys.p384, coordSize: 48 },
        { alg: 'ES512', curve: 'P-521', keyPair: testKeys.p521, coordSize: 66 }
      ];

      for (const { alg, curve, keyPair, coordSize } of algorithms) {
        const pubKeyUncompressed = keyPair.public;
        const x = Buffer.from(pubKeyUncompressed.slice(1, 1 + coordSize));
        const y = Buffer.from(pubKeyUncompressed.slice(1 + coordSize, 1 + 2 * coordSize));
        
        const headers: COSEHeaders = {
          p: { alg },
          u: {}
        };

        const signer: COSESigner = {
          key: {
            kty: 'EC2',
            crv: curve,
            x: x,
            y: y,
            d: Buffer.from(keyPair.private)
          }
        };

        const verifier: COSEVerifier = {
          key: {
            kty: 'EC2',
            crv: curve,
            x: x,
            y: y
          }
        };

        // Test signing and verification
        const signedData = await sign.create(headers, payload, signer);
        const verifiedPayload = sign.verifySync(signedData, verifier);
        
        expect(verifiedPayload).toEqual(payload);
      }
    });
  });

  describe('Payload Format Handling', () => {
    const testSigner: COSESigner = {
      key: {
        kty: 'EC2',
        crv: 'P-256',
        x: Buffer.from(new Uint8Array(testKeys.p256.public).slice(1, 33)),
        y: Buffer.from(new Uint8Array(testKeys.p256.public).slice(33, 65)),
        d: Buffer.from(testKeys.p256.private)
      }
    };

    const headers: COSEHeaders = {
      p: { alg: 'ES256' } // ES256
    };

    it('should handle raw bytes payload format', async () => {
      const rawPayload = Buffer.from('Hello, raw bytes!');
      
      const signedData = await sign.create(headers, rawPayload, testSigner, {
        payloadFormat: 'raw'
      });
      
      expect(Buffer.isBuffer(signedData)).toBe(true);
    });

    it('should handle CBOR-encoded payload format', async () => {
      const objectPayload = { message: 'Hello, CBOR!' };
      
      const signedData = await sign.create(headers, objectPayload, testSigner, {
        payloadFormat: 'cbor-encoded'
      });
      
      expect(Buffer.isBuffer(signedData)).toBe(true);
    });

    it('should auto-detect raw bytes', async () => {
      const rawPayload = Buffer.from('Hello, auto-detect!');
      
      const signedData = await sign.create(headers, rawPayload, testSigner, {
        payloadFormat: 'auto-detect'
      });
      
      expect(Buffer.isBuffer(signedData)).toBe(true);
    });

    it('should auto-detect tagged values', async () => {
      const typedArray = new Uint8Array([1, 2, 3, 4, 5]);
      const taggedPayload = sign.createTypedArrayPayload(typedArray);
      
      const signedData = await sign.create(headers, taggedPayload, testSigner, {
        payloadFormat: 'auto-detect'
      });
      
      expect(Buffer.isBuffer(signedData)).toBe(true);
    });

    it('should create typed array payload with tag(64)', () => {
      const typedArray = new Uint8Array([1, 2, 3, 4, 5]);
      const taggedPayload = sign.createTypedArrayPayload(typedArray);
      
      expect(taggedPayload.tag).toBe(64);
      expect(taggedPayload.value).toEqual(typedArray);
    });

    it('should create CBOR payload with tag(24)', () => {
      const data = { message: 'test' };
      const cborPayload = sign.createCborPayload(data);
      
      expect(cborPayload.tag).toBe(24);
      expect(Buffer.isBuffer(cborPayload.value)).toBe(true);
    });

    it('should return raw bytes payload as-is', () => {
      const rawBytes = Buffer.from('test data');
      const bytesPayload = sign.createBytesPayload(rawBytes);
      
      expect(bytesPayload).toBe(rawBytes);
      expect(Buffer.isBuffer(bytesPayload)).toBe(true);
    });
  });
});
