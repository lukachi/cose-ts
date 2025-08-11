import * as cborUtils from './cbor-utils.js';
// @ts-ignore
import { create as createMac } from 'aes-cbc-mac';
import * as common from './common.js';
import { hmac } from '@noble/hashes/hmac';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2';
import type { COSEHeaders, COSERecipient, COSEOptions } from './types.js';

// Wrapper functions for CBOR operations with canonical encoding
function encode(data: any): Buffer {
  const encoded = cborUtils.encode(data);
  return Buffer.from(encoded);
}

function decode(data: Buffer): any {
  return cborUtils.decode(data);
}

const EMPTY_BUFFER = common.EMPTY_BUFFER;

export const MAC0Tag = 17;
export const MACTag = 97;

interface AlgFromTagsMap {
  [key: number]: string;
}

const AlgFromTags: AlgFromTagsMap = {
  4: 'SHA-256_64',
  5: 'SHA-256',
  6: 'SHA-384',
  7: 'SHA-512',
  14: 'AES-MAC-128/64',
  15: 'AES-MAC-256/64',
  25: 'AES-MAC-128/128',
  26: 'AES-MAC-256/128'
};

interface COSEAlgToNodeAlgMap {
  [key: string]: string;
}

const COSEAlgToNodeAlg: COSEAlgToNodeAlgMap = {
  'SHA-256_64': 'sha256',
  'SHA-256': 'sha256',
  HS256: 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
  'AES-MAC-128/64': 'aes-cbc-mac-64',
  'AES-MAC-128/128': 'aes-cbc-mac-128',
  'AES-MAC-256/64': 'aes-cbc-mac-64',
  'AES-MAC-256/128': 'aes-cbc-mac-128'
};

interface CutToMap {
  [key: number]: number;
}

const CutTo: CutToMap = {
  4: 8,
  5: 32,
  6: 48,
  7: 64
};

interface ContextMap {
  [key: number]: string;
}

const context: ContextMap = {};
context[MAC0Tag] = 'MAC0';
context[MACTag] = 'MAC';

function doMac(context: string, p: Buffer, externalAAD: Buffer, payload: Buffer, alg: string, key: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    const MACstructure = [
      context, // 'MAC0' or 'MAC1', // context
      p, // protected
      externalAAD, // bstr,
      payload // bstr
    ];

    const toBeMACed = encode(MACstructure);
    if (alg === 'aes-cbc-mac-64') {
      const mac = createMac(key, toBeMACed, 8);
      resolve(mac);
    } else if (alg === 'aes-cbc-mac-128') {
      const mac = createMac(key, toBeMACed, 16);
      resolve(mac);
    } else {
      // Use @noble/hashes for HMAC
      let hashFn;
      switch (alg) {
        case 'sha256':
          hashFn = sha256;
          break;
        case 'sha384':
          hashFn = sha384;
          break;
        case 'sha512':
          hashFn = sha512;
          break;
        default:
          throw new Error(`Unsupported hash algorithm: ${alg}`);
      }
      
      const macResult = hmac(hashFn, new Uint8Array(key), new Uint8Array(toBeMACed));
      resolve(Buffer.from(macResult));
    }
  });
}

export async function create(
  headers: COSEHeaders, 
  payload: Buffer, 
  recipients: COSERecipient[] | COSERecipient, 
  externalAAD?: Buffer, 
  options?: COSEOptions
): Promise<Buffer> {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;
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

    const predictableP = (!pMap.size) ? EMPTY_BUFFER : encode(pMap);
    let encodedP: Buffer;
    if (pMap.size === 0 && options.encodep === 'empty') {
      encodedP = EMPTY_BUFFER;
    } else {
      encodedP = encode(pMap);
    }
    // TODO check crit headers
    if (recipients.length > 1) {
      throw new Error('MACing with multiple recipients is not implemented');
    }
    const recipient = recipients[0];
    let tag = await doMac('MAC', predictableP, externalAAD, payload, COSEAlgToNodeAlg[AlgFromTags[alg]], recipient.key as Buffer);
    tag = tag.slice(0, CutTo[alg]);
    const ru = common.TranslateHeaders(recipient.u || {});
    const rp = EMPTY_BUFFER;
    const maced = [encodedP, uMap, payload, tag, [[rp, ru, EMPTY_BUFFER]]];
    return encode(options.excludetag ? maced : cborUtils.createTag(MACTag, maced));
  } else {
    const predictableP = (!pMap.size) ? EMPTY_BUFFER : encode(pMap);
    let encodedP: Buffer;
    if (pMap.size === 0 && options.encodep === 'empty') {
      encodedP = EMPTY_BUFFER;
    } else {
      encodedP = encode(pMap);
    }
    let tag = await doMac('MAC0', predictableP, externalAAD, payload, COSEAlgToNodeAlg[AlgFromTags[alg]], recipients.key as Buffer);
    tag = tag.slice(0, CutTo[alg]);
    const maced = [encodedP, uMap, payload, tag];
    return encode(options.excludetag ? maced : cborUtils.createTag(MAC0Tag, maced));
  }
}

export async function read(data: Buffer, key: Buffer, externalAAD?: Buffer, options?: COSEOptions): Promise<Buffer> {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;

  let obj = decode(data);

  let type = options.defaultType ? options.defaultType : MAC0Tag;
  if (cborUtils.isTagged(obj)) {
    if (obj.tag !== MAC0Tag && obj.tag !== MACTag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = Number(obj.tag);
    obj = obj.value;
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (type === MAC0Tag && obj.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }
  if (type === MACTag && obj.length !== 5) {
    throw new Error('Expecting Array of lenght 5');
  }

  let [p, u, payload, tag] = obj;
  
  // Handle protected headers - ensure p is a Buffer
  if (Array.isArray(p)) {
    p = Buffer.from(p);
  } else if (p && typeof p === 'object' && p.data && Array.isArray(p.data)) {
    // Handle cbor2 format: { data: [...], type: 'Buffer' }
    p = Buffer.from(p.data);
  } else if (!Buffer.isBuffer(p)) {
    p = Buffer.alloc(0);
  }
  
  let pMap: Map<number, any> = new Map();
  if (p.length > 0) {
    pMap = decode(p);
  }
  
  // Handle unprotected headers - ensure it's a Map
  if (u && typeof u === 'object' && !u.size && !Buffer.isBuffer(u)) {
    // Handle plain objects that might come from cbor2
    const tempMap = new Map();
    for (const [key, value] of Object.entries(u)) {
      tempMap.set(parseInt(key), value);
    }
    u = tempMap;
  }
  u = (!u || !u.size) ? new Map() : u;

  // Extract algorithm from protected headers first, then unprotected headers
  // The algorithm is stored as a numeric ID, not a string
  const alg = pMap.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
  
  // Use the original encoded protected headers for MAC verification
  // NOT re-encoded from the decoded map, as that might have different canonical encoding
  const encodedP = p; // Use original bytes
  
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg]]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg]);
  }

  let calcTag = await doMac(context[type], encodedP, externalAAD, payload, COSEAlgToNodeAlg[AlgFromTags[alg]], key);
  calcTag = calcTag.slice(0, CutTo[alg]);
  if (tag.toString('hex') !== calcTag.toString('hex')) {
    throw new Error('Tag mismatch');
  }
  return payload;
}
