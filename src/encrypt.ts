import * as cborUtils from './cbor-utils.js';
import * as common from './common.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { gcm } from '@noble/ciphers/aes';
import { p256, p521 } from '@noble/curves/nist';
import type { COSEHeaders, COSERecipient, COSEOptions, COSEKey } from './types.js';

// Wrapper functions for CBOR operations with canonical encoding
function encode(data: any): Buffer {
  const encoded = cborUtils.encode(data);
  return Buffer.from(encoded);
}

function decode(data: Buffer): any {
  return cborUtils.decode(data);
}

const EMPTY_BUFFER = common.EMPTY_BUFFER;
export const EncryptTag = 96;
export const Encrypt0Tag = 16;

const runningInNode = common.runningInNode;

interface TagToAlgMap {
  [key: number]: string;
}

const TagToAlg: TagToAlgMap = {
  1: 'A128GCM',
  2: 'A192GCM',
  3: 'A256GCM',
  10: 'AES-CCM-16-64-128',
  11: 'AES-CCM-16-64-256',
  12: 'AES-CCM-64-64-128',
  13: 'AES-CCM-64-64-256',
  30: 'AES-CCM-16-128-128',
  31: 'AES-CCM-16-128-256',
  32: 'AES-CCM-64-128-128',
  33: 'AES-CCM-64-128-256'
};

interface BooleanMap {
  [key: number]: boolean;
}

const isNodeAlg: BooleanMap = {
  1: true, // A128GCM
  2: true, // A192GCM
  3: true // A256GCM
};

const isCCMAlg: BooleanMap = {
  10: true, // AES-CCM-16-64-128
  11: true, // AES-CCM-16-64-256
  12: true, // AES-CCM-64-64-128
  13: true, // AES-CCM-64-64-256
  30: true, // AES-CCM-16-128-128
  31: true, // AES-CCM-16-128-256
  32: true, // AES-CCM-64-128-128
  33: true // AES-CCM-64-128-256
};

interface NumberMap {
  [key: number | string]: number;
}

const authTagLength: NumberMap = {
  1: 16,
  2: 16,
  3: 16,
  10: 8, // AES-CCM-16-64-128
  11: 8, // AES-CCM-16-64-256
  12: 8, // AES-CCM-64-64-128
  13: 8, // AES-CCM-64-64-256
  30: 16, // AES-CCM-16-128-128
  31: 16, // AES-CCM-16-128-256
  32: 16, // AES-CCM-64-128-128
  33: 16 // AES-CCM-64-128-256
};

const ivLength: NumberMap = {
  1: 12, // A128GCM
  2: 12, // A192GCM
  3: 12, // A256GCM
  10: 13, // AES-CCM-16-64-128
  11: 13, // AES-CCM-16-64-256
  12: 7, // AES-CCM-64-64-128
  13: 7, // AES-CCM-64-64-256
  30: 13, // AES-CCM-16-128-128
  31: 13, // AES-CCM-16-128-256
  32: 7, // AES-CCM-64-128-128
  33: 7 // AES-CCM-64-128-256
};

const keyLength: NumberMap = {
  1: 16, // A128GCM
  2: 24, // A192GCM
  3: 32, // A256GCM
  10: 16, // AES-CCM-16-64-128
  11: 32, // AES-CCM-16-64-256
  12: 16, // AES-CCM-64-64-128
  13: 32, // AES-CCM-64-64-256
  30: 16, // AES-CCM-16-128-128
  31: 32, // AES-CCM-16-128-256
  32: 16, // AES-CCM-64-128-128
  33: 32, // AES-CCM-64-128-256
  'P-521': 66,
  'P-256': 32
};

interface HKDFAlgMap {
  [key: string]: typeof sha256 | typeof sha512;
}

const HKDFAlg: HKDFAlgMap = {
  'ECDH-ES': sha256,
  'ECDH-ES-512': sha512,
  'ECDH-SS': sha256,
  'ECDH-SS-512': sha512
};

/**
 * Generate ECDH key pair using @noble/curves
 */
function generateECDHKeyPair(curve: string, privateKey?: Buffer): { publicKey: Buffer; privateKey: Buffer } {
  switch (curve) {
    case 'P-256': {
      const privKey = privateKey || Buffer.from(p256.utils.randomSecretKey());
      const pubKey = p256.getPublicKey(new Uint8Array(privKey), false); // uncompressed format
      return { 
        publicKey: Buffer.from(pubKey), 
        privateKey: privKey 
      };
    }
    case 'P-521': {
      const privKey = privateKey || Buffer.from(p521.utils.randomSecretKey());
      const pubKey = p521.getPublicKey(new Uint8Array(privKey), false); // uncompressed format
      return { 
        publicKey: Buffer.from(pubKey), 
        privateKey: privKey 
      };
    }
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

/**
 * Compute ECDH shared secret using @noble/curves
 */
function computeECDHSecret(curve: string, privateKey: Buffer, publicKey: Buffer): Buffer {
  switch (curve) {
    case 'P-256': {
      const sharedSecret = p256.getSharedSecret(new Uint8Array(privateKey), new Uint8Array(publicKey));
      return Buffer.from(sharedSecret);
    }
    case 'P-521': {
      const sharedSecret = p521.getSharedSecret(new Uint8Array(privateKey), new Uint8Array(publicKey));
      return Buffer.from(sharedSecret);
    }
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

/**
 * Check if the algorithm is an ECDH-based key agreement algorithm
 */
function isECDHAlgorithm(alg: string): boolean {
  return alg === 'ECDH-ES' || alg === 'ECDH-ES-512' || alg === 'ECDH-SS' || alg === 'ECDH-SS-512';
}

/**
 * Check if the recipient uses ECDH key agreement
 */
function usesECDHKeyAgreement(recipient: COSERecipient): boolean {
  return !!(recipient.p && 
         typeof recipient.p.alg === 'string' && 
         isECDHAlgorithm(recipient.p.alg) &&
         recipient.key &&
         typeof recipient.key === 'object' &&
         'crv' in recipient.key &&
         'x' in recipient.key &&
         'y' in recipient.key &&
         'd' in recipient.key);
}

function createAAD(p: Map<number, any>, context: string, externalAAD: Buffer): Buffer {
  const pEncoded = (!p.size) ? EMPTY_BUFFER : encode(p);
  const encStructure = [
    context,
    pEncoded,
    externalAAD
  ];
  return encode(encStructure);
}

function _randomSource(bytes: number): Buffer {
  return Buffer.from(randomBytes(bytes));
}

function nobleEncrypt(payload: Buffer, key: Buffer, alg: number, iv: Buffer, aad: Buffer, ccm = false): Buffer {
  if (ccm) {
    throw new Error(`CCM algorithms (${TagToAlg[alg]}) are not yet supported with @noble/ciphers. Use Node.js environment for CCM support.`);
  }
  
  // Only support GCM algorithms with @noble/ciphers
  if (!isNodeAlg[alg]) {
    throw new Error(`Algorithm ${TagToAlg[alg]} is not supported with @noble/ciphers`);
  }
  
  // Convert Buffers to Uint8Array for @noble/ciphers
  const cipher = gcm(new Uint8Array(key), new Uint8Array(iv), new Uint8Array(aad));
  const encrypted = cipher.encrypt(new Uint8Array(payload));
  return Buffer.from(encrypted);
}

function createContext(rp: Buffer, alg: number, partyUNonce?: Buffer | null): Buffer {
  return encode([
    alg,
    [
      null,
      (partyUNonce || null),
      null
    ],
    [
      null,
      null,
      null
    ],
    [
      keyLength[alg] * 8,
      rp
    ]
  ]);
}

export function create(headers: COSEHeaders, payload: Buffer, recipients: COSERecipient[] | COSERecipient, options?: COSEOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      options = options || {};
      const externalAAD = options.externalAAD || EMPTY_BUFFER;
      const randomSource = options.randomSource || _randomSource;
      let u = headers.u || {};
      let p = headers.p || {};

      const pMap = common.TranslateHeaders(p);
      const uMap = common.TranslateHeaders(u);

      const alg = pMap.get(common.HeaderParameters.alg) || uMap.get(common.HeaderParameters.alg);

      if (!alg) {
        throw new Error('Missing mandatory parameter \'alg\'');
      }

      if (Array.isArray(recipients)) {
        if (recipients.length === 0) {
          throw new Error('There has to be at least one recipient');
        }
        if (recipients.length > 1) {
          throw new Error('Encrypting with multiple recipients is not implemented');
        }

        let iv: Buffer;
        if (options.contextIv) {
          const partialIv = randomSource(2);
          iv = common.xor(partialIv, options.contextIv);
          uMap.set(common.HeaderParameters.Partial_IV, partialIv);
        } else {
          iv = randomSource(ivLength[alg]);
          uMap.set(common.HeaderParameters.IV, iv);
        }

        const aad = createAAD(pMap, 'Encrypt', externalAAD);

        let key: Buffer;
        let recipientStruct: any[][];
        
        if (usesECDHKeyAgreement(recipients[0])) {
          const recipientKey = recipients[0].key as COSEKey;
          const recipientAlg = recipients[0].p!.alg as string;
          
          // Generate key pair for sender
          let pk = randomSource(keyLength[recipientKey.crv!]);
          if (recipientAlg === 'ECDH-ES' || recipientAlg === 'ECDH-ES-512') {
            pk = randomSource(keyLength[recipientKey.crv!]);
            pk[0] = (recipientKey.crv !== 'P-521' || pk[0] === 1) ? pk[0] : 0;
          } else {
            pk = recipients[0].sender!.d!;
          }

          const senderKeyPair = generateECDHKeyPair(recipientKey.crv!, pk);
          const recipientPublicKey = Buffer.concat([
            Buffer.from('04', 'hex'),
            recipientKey.x!,
            recipientKey.y!
          ]);

          const generatedKey = common.TranslateKey({
            crv: recipientKey.crv!,
            x: senderKeyPair.publicKey.slice(1, keyLength[recipientKey.crv!] + 1),
            y: senderKeyPair.publicKey.slice(keyLength[recipientKey.crv!] + 1, keyLength[recipientKey.crv!] * 2 + 1),
            kty: 'EC2'
          });
          const rp = encode(common.TranslateHeaders(recipients[0].p!));
          const ikm = computeECDHSecret(recipientKey.crv!, senderKeyPair.privateKey, recipientPublicKey);
          let partyUNonce: Buffer | null = null;
          if (recipientAlg === 'ECDH-SS' || recipientAlg === 'ECDH-SS-512') {
            // Generate a random nonce for Static-Static key agreement
            // Using 32 bytes (256 bits) which provides sufficient entropy
            partyUNonce = randomSource(32);
          }
          const context = createContext(rp, alg, partyUNonce);
          const nrBytes = keyLength[alg];
          const hashFn = HKDFAlg[recipientAlg];
          key = Buffer.from(hkdf(hashFn, new Uint8Array(ikm), undefined, new Uint8Array(context), nrBytes));
          let ru = recipients[0].u || {};

          if (recipientAlg === 'ECDH-ES' || recipientAlg === 'ECDH-ES-512') {
            ru.ephemeral_key = generatedKey;
          } else {
            ru.static_key = generatedKey;
          }

          ru.partyUNonce = partyUNonce;
          const ruMap = common.TranslateHeaders(ru);

          recipientStruct = [[rp, ruMap, EMPTY_BUFFER]];
        } else {
          key = recipients[0].key as Buffer;
          const ruMap = common.TranslateHeaders(recipients[0].u || {});
          recipientStruct = [[EMPTY_BUFFER, ruMap, EMPTY_BUFFER]];
        }

        let ciphertext: Buffer;
        if (isNodeAlg[alg]) {
          ciphertext = nobleEncrypt(payload, key, alg, iv, aad);
        } else if (isCCMAlg[alg] && runningInNode()) {
          ciphertext = nobleEncrypt(payload, key, alg, iv, aad, true);
        } else {
          throw new Error('No implementation for algorithm, ' + alg);
        }

        let encodedP: Buffer;
        if (pMap.size === 0 && options.encodep === 'empty') {
          encodedP = EMPTY_BUFFER;
        } else {
          encodedP = encode(pMap);
        }

        const encrypted = [encodedP, uMap, ciphertext, recipientStruct];
        resolve(encode(options.excludetag ? encrypted : cborUtils.createTag(EncryptTag, encrypted)));
      } else {
        let iv: Buffer;
        if (options.contextIv) {
          const partialIv = randomSource(2);
          iv = common.xor(partialIv, options.contextIv);
          uMap.set(common.HeaderParameters.Partial_IV, partialIv);
        } else {
          iv = randomSource(ivLength[alg]);
          uMap.set(common.HeaderParameters.IV, iv);
        }

        const key = recipients.key as Buffer;

        const aad = createAAD(pMap, 'Encrypt0', externalAAD);
        let ciphertext: Buffer;
        if (isNodeAlg[alg]) {
          ciphertext = nobleEncrypt(payload, key, alg, iv, aad);
        } else if (isCCMAlg[alg] && runningInNode()) {
          ciphertext = nobleEncrypt(payload, key, alg, iv, aad, true);
        } else {
          throw new Error('No implementation for algorithm, ' + alg);
        }

        let encodedP: Buffer;
        if (pMap.size === 0 && options.encodep === 'empty') {
          encodedP = EMPTY_BUFFER;
        } else {
          encodedP = encode(pMap);
        }
        const encrypted = [encodedP, uMap, ciphertext];
        resolve(encode(options.excludetag ? encrypted : cborUtils.createTag(Encrypt0Tag, encrypted)));
      }
    } catch (error) {
      reject(error);
    }
  });
}

function nobleDecrypt(ciphertext: Buffer, key: Buffer, alg: number, iv: Buffer, tag: Buffer, aad: Buffer, ccm = false): Buffer {
  if (ccm) {
    throw new Error(`CCM algorithms (${TagToAlg[alg]}) are not yet supported with @noble/ciphers. Use Node.js environment for CCM support.`);
  }
  
  // Only support GCM algorithms with @noble/ciphers
  if (!isNodeAlg[alg]) {
    throw new Error(`Algorithm ${TagToAlg[alg]} is not supported with @noble/ciphers`);
  }
  
  // Combine ciphertext and tag for @noble/ciphers
  const ciphertextWithTag = Buffer.concat([ciphertext, tag]);
  // Convert Buffers to Uint8Array for @noble/ciphers
  const cipher = gcm(new Uint8Array(key), new Uint8Array(iv), new Uint8Array(aad));
  const decrypted = cipher.decrypt(new Uint8Array(ciphertextWithTag));
  return Buffer.from(decrypted);
}

export async function read(data: Buffer, key: Buffer, options?: COSEOptions): Promise<Buffer> {
  options = options || {};
  const externalAAD = options.externalAAD || EMPTY_BUFFER;
  let obj = decode(data);
  let msgTag = options.defaultType ? options.defaultType : EncryptTag;
  if (cborUtils.isTagged(obj)) {
    const tagNumber = cborUtils.getTagNumber(obj);
    if (tagNumber !== EncryptTag && tagNumber !== Encrypt0Tag) {
      throw new Error('Unknown tag, ' + tagNumber);
    }
    msgTag = Number(tagNumber);
    obj = cborUtils.getTagValue(obj);
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (msgTag === EncryptTag && obj.length !== 4) {
    throw new Error('Expecting Array of length 4 for COSE Encrypt message');
  }

  if (msgTag === Encrypt0Tag && obj.length !== 3) {
    throw new Error('Expecting Array of length 3 for COSE Encrypt0 message');
  }

  let [p, u, ciphertext] = obj;

  // Ensure p is a Buffer 
  if (Array.isArray(p)) {
    p = Buffer.from(p);
  } else if (p && typeof p === 'object' && p.data && Array.isArray(p.data)) {
    // Handle cbor2 format: { data: [...], type: 'Buffer' }
    p = Buffer.from(p.data);
  } else if (p instanceof Uint8Array) {
    // Handle Uint8Array (common case for protected headers)
    p = Buffer.from(p);
  } else if (!Buffer.isBuffer(p)) {
    p = Buffer.alloc(0); // Convert to empty buffer if not a buffer
  }

  // Ensure ciphertext is a Buffer
  if (Array.isArray(ciphertext)) {
    ciphertext = Buffer.from(ciphertext);
  } else if (ciphertext && typeof ciphertext === 'object' && ciphertext.data && Array.isArray(ciphertext.data)) {
    // Handle cbor2 format: { data: [...], type: 'Buffer' }
    ciphertext = Buffer.from(ciphertext.data);
  }

  const pMap = (p.length === 0) ? new Map() : decode(p);
  
  // Handle the case where u might be a plain object from cbor2
  if (u && typeof u === 'object' && !u.size && !Buffer.isBuffer(u)) {
    // Convert plain object to Map if needed
    if (!(u instanceof Map)) {
      const uMap = new Map();
      for (const [key, value] of Object.entries(u)) {
        uMap.set(Number(key), value);
      }
      u = uMap;
    }
  }
  u = (!u || (u instanceof Map && !u.size)) ? new Map() : u;

  const pDecoded = (!(pMap as any).size && !(typeof pMap === 'object' && Object.keys(pMap).length)) ? new Map() : pMap;
  const uDecoded = (!u || (u instanceof Map && !u.size)) ? new Map() : u;

  const alg = pDecoded.get(common.HeaderParameters.alg) || uDecoded.get(common.HeaderParameters.alg);
  
  if (!TagToAlg[alg]) {
    throw new Error('Unknown or unsupported algorithm ' + alg);
  }

  let iv = uDecoded.get(common.HeaderParameters.IV);
  let partialIv = uDecoded.get(common.HeaderParameters.Partial_IV);
  
  // Convert iv from cbor2 format if needed
  if (iv && typeof iv === 'object' && iv.data && Array.isArray(iv.data)) {
    iv = Buffer.from(iv.data);
  } else if (iv && Array.isArray(iv)) {
    iv = Buffer.from(iv);
  }
  
  // Convert partialIv from cbor2 format if needed  
  if (partialIv && typeof partialIv === 'object' && partialIv.data && Array.isArray(partialIv.data)) {
    partialIv = Buffer.from(partialIv.data);
  } else if (partialIv && Array.isArray(partialIv)) {
    partialIv = Buffer.from(partialIv);
  }
  
  if (iv && partialIv) {
    throw new Error('IV and Partial IV parameters MUST NOT both be present in the same security layer');
  }
  if (partialIv && !options.contextIv) {
    throw new Error('Context IV must be provided when Partial IV is used');
  }
  if (partialIv && options.contextIv) {
    iv = common.xor(partialIv, options.contextIv);
  }

  const tagLength = authTagLength[alg];
  const tag = ciphertext.slice(ciphertext.length - tagLength, ciphertext.length);
  ciphertext = ciphertext.slice(0, ciphertext.length - tagLength);

  const aad = createAAD(pDecoded as Map<number, any>, (msgTag === EncryptTag ? 'Encrypt' : 'Encrypt0'), externalAAD);
  if (isNodeAlg[alg]) {
    return nobleDecrypt(ciphertext, key, alg, iv, tag, aad);
  } else if (isCCMAlg[alg] && runningInNode()) {
    return nobleDecrypt(ciphertext, key, alg, iv, tag, aad, true);
  } else {
    throw new Error('No implementation for algorithm, ' + alg);
  }
}
