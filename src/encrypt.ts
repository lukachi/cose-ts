import * as cbor from 'cbor';
import * as crypto from 'crypto';
import * as common from './common.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import type { COSEHeaders, COSERecipient, COSEOptions, COSEKey } from './types.js';

const Tagged = cbor.Tagged;

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

interface COSEAlgToNodeAlgMap {
  [key: string]: string;
}

const COSEAlgToNodeAlg: COSEAlgToNodeAlgMap = {
  A128GCM: 'aes-128-gcm',
  A192GCM: 'aes-192-gcm',
  A256GCM: 'aes-256-gcm',

  'AES-CCM-16-64-128': 'aes-128-ccm',
  'AES-CCM-16-64-256': 'aes-256-ccm',
  'AES-CCM-64-64-128': 'aes-128-ccm',
  'AES-CCM-64-64-256': 'aes-256-ccm',
  'AES-CCM-16-128-128': 'aes-128-ccm',
  'AES-CCM-16-128-256': 'aes-256-ccm',
  'AES-CCM-64-128-128': 'aes-128-ccm',
  'AES-CCM-64-128-256': 'aes-256-ccm'
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

interface NodeCRVMap {
  [key: string]: string;
}

const nodeCRV: NodeCRVMap = {
  'P-521': 'secp521r1',
  'P-256': 'prime256v1'
};

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
  const pEncoded = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
  const encStructure = [
    context,
    pEncoded,
    externalAAD
  ];
  return cbor.encode(encStructure);
}

function _randomSource(bytes: number): Buffer {
  return crypto.randomBytes(bytes);
}

function nodeEncrypt(payload: Buffer, key: Buffer, alg: number, iv: Buffer, aad: Buffer, ccm = false): Buffer {
  const nodeAlg = COSEAlgToNodeAlg[TagToAlg[alg]];
  const cipher = ccm 
    ? crypto.createCipheriv(nodeAlg, key, iv, { authTagLength: authTagLength[alg] } as any)
    : crypto.createCipheriv(nodeAlg, key, iv);
  const aadOptions = ccm ? { plaintextLength: Buffer.byteLength(payload) } : undefined;
  (cipher as any).setAAD(aad, aadOptions);
  return Buffer.concat([
    cipher.update(payload),
    cipher.final(),
    (cipher as any).getAuthTag()
  ]);
}

function createContext(rp: Buffer, alg: number, partyUNonce?: Buffer | null): Buffer {
  return cbor.encode([
    alg, // AlgorithmID
    [ // PartyUInfo
      null, // identity
      (partyUNonce || null), // nonce
      null // other
    ],
    [ // PartyVInfo
      null, // identity
      null, // nonce
      null // other
    ],
    [
      keyLength[alg] * 8, // keyDataLength
      rp // protected
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
          
          const recipient = crypto.createECDH(nodeCRV[recipientKey.crv!]);
          const generated = crypto.createECDH(nodeCRV[recipientKey.crv!]);
          recipient.setPrivateKey(recipientKey.d!);
          let pk = randomSource(keyLength[recipientKey.crv!]);
          if (recipientAlg === 'ECDH-ES' || recipientAlg === 'ECDH-ES-512') {
            pk = randomSource(keyLength[recipientKey.crv!]);
            pk[0] = (recipientKey.crv !== 'P-521' || pk[0] === 1) ? pk[0] : 0;
          } else {
            pk = recipients[0].sender!.d!;
          }

          generated.setPrivateKey(pk);
          const senderPublicKey = generated.getPublicKey();
          const recipientPublicKey = Buffer.concat([
            Buffer.from('04', 'hex'),
            recipientKey.x!,
            recipientKey.y!
          ]);

          const generatedKey = common.TranslateKey({
            crv: recipientKey.crv!,
            x: senderPublicKey.slice(1, keyLength[recipientKey.crv!] + 1),
            y: senderPublicKey.slice(keyLength[recipientKey.crv!] + 1, keyLength[recipientKey.crv!] * 2 + 1),
            kty: 'EC2'
          });
          const rp = cbor.encode(common.TranslateHeaders(recipients[0].p!));
          const ikm = generated.computeSecret(recipientPublicKey);
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
          ciphertext = nodeEncrypt(payload, key, alg, iv, aad);
        } else if (isCCMAlg[alg] && runningInNode()) {
          ciphertext = nodeEncrypt(payload, key, alg, iv, aad, true);
        } else {
          throw new Error('No implementation for algorithm, ' + alg);
        }

        let encodedP: Buffer;
        if (pMap.size === 0 && options.encodep === 'empty') {
          encodedP = EMPTY_BUFFER;
        } else {
          encodedP = cbor.encode(pMap);
        }

        const encrypted = [encodedP, uMap, ciphertext, recipientStruct];
        resolve(cbor.encode(options.excludetag ? encrypted : new Tagged(EncryptTag, encrypted)));
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
          ciphertext = nodeEncrypt(payload, key, alg, iv, aad);
        } else if (isCCMAlg[alg] && runningInNode()) {
          ciphertext = nodeEncrypt(payload, key, alg, iv, aad, true);
        } else {
          throw new Error('No implementation for algorithm, ' + alg);
        }

        let encodedP: Buffer;
        if (pMap.size === 0 && options.encodep === 'empty') {
          encodedP = EMPTY_BUFFER;
        } else {
          encodedP = cbor.encode(pMap);
        }
        const encrypted = [encodedP, uMap, ciphertext];
        resolve(cbor.encode(options.excludetag ? encrypted : new Tagged(Encrypt0Tag, encrypted)));
      }
    } catch (error) {
      reject(error);
    }
  });
}

function nodeDecrypt(ciphertext: Buffer, key: Buffer, alg: number, iv: Buffer, tag: Buffer, aad: Buffer, ccm = false): Buffer {
  const nodeAlg = COSEAlgToNodeAlg[TagToAlg[alg]];
  const decipher = ccm 
    ? crypto.createDecipheriv(nodeAlg, key, iv, { authTagLength: authTagLength[alg] } as any)
    : crypto.createDecipheriv(nodeAlg, key, iv);
  const aadOptions = ccm ? { plaintextLength: Buffer.byteLength(ciphertext) } : undefined;
  (decipher as any).setAuthTag(tag);
  (decipher as any).setAAD(aad, aadOptions);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export async function read(data: Buffer, key: Buffer, options?: COSEOptions): Promise<Buffer> {
  options = options || {};
  const externalAAD = options.externalAAD || EMPTY_BUFFER;
  let obj = await cbor.decodeFirst(data);
  let msgTag = options.defaultType ? options.defaultType : EncryptTag;
  if (obj instanceof Tagged) {
    if (obj.tag !== EncryptTag && obj.tag !== Encrypt0Tag) {
      throw new Error('Unknown tag, ' + obj.tag);
    }
    msgTag = obj.tag;
    obj = obj.value;
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

  const pMap = (p.length === 0) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
  const pDecoded = (!(pMap as Map<number, any>).size) ? EMPTY_BUFFER : pMap;
  const uDecoded = (!u.size) ? EMPTY_BUFFER : u;

  const alg = (pDecoded !== EMPTY_BUFFER) ? (pDecoded as Map<number, any>).get(common.HeaderParameters.alg) : (uDecoded !== EMPTY_BUFFER) ? (uDecoded as Map<number, any>).get(common.HeaderParameters.alg) : undefined;
  if (!TagToAlg[alg]) {
    throw new Error('Unknown or unsupported algorithm ' + alg);
  }

  let iv = (uDecoded as Map<number, any>).get(common.HeaderParameters.IV);
  const partialIv = (uDecoded as Map<number, any>).get(common.HeaderParameters.Partial_IV);
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
    return nodeDecrypt(ciphertext, key, alg, iv, tag, aad);
  } else if (isCCMAlg[alg] && runningInNode()) {
    return nodeDecrypt(ciphertext, key, alg, iv, tag, aad, true);
  } else {
    throw new Error('No implementation for algorithm, ' + alg);
  }
}
