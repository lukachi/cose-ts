import * as cbor from 'cbor-x';
// @ts-ignore
import { create as createMac } from 'aes-cbc-mac';
import * as crypto from 'crypto';
import * as common from './common.js';
import type { COSEHeaders, COSERecipient, COSEOptions } from './types.js';

const Tagged = cbor.Tag;
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

    const toBeMACed = cbor.encode(MACstructure);
    if (alg === 'aes-cbc-mac-64') {
      const mac = createMac(key, toBeMACed, 8);
      resolve(mac);
    } else if (alg === 'aes-cbc-mac-128') {
      const mac = createMac(key, toBeMACed, 16);
      resolve(mac);
    } else {
      const hmac = crypto.createHmac(alg, key);
      hmac.end(toBeMACed, function () {
        resolve(hmac.read());
      });
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

    const predictableP = (!pMap.size) ? EMPTY_BUFFER : cbor.encode(pMap);
    let encodedP: Buffer;
    if (pMap.size === 0 && options.encodep === 'empty') {
      encodedP = EMPTY_BUFFER;
    } else {
      encodedP = cbor.encode(pMap);
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
    return cbor.encode(options.excludetag ? maced : new Tagged(maced, MACTag));
  } else {
    const predictableP = (!pMap.size) ? EMPTY_BUFFER : cbor.encode(pMap);
    let encodedP: Buffer;
    if (pMap.size === 0 && options.encodep === 'empty') {
      encodedP = EMPTY_BUFFER;
    } else {
      encodedP = cbor.encode(pMap);
    }
    let tag = await doMac('MAC0', predictableP, externalAAD, payload, COSEAlgToNodeAlg[AlgFromTags[alg]], recipients.key as Buffer);
    tag = tag.slice(0, CutTo[alg]);
    const maced = [encodedP, uMap, payload, tag];
    return cbor.encode(options.excludetag ? maced : new Tagged(maced, MAC0Tag));
  }
}

export async function read(data: Buffer, key: Buffer, externalAAD?: Buffer, options?: COSEOptions): Promise<Buffer> {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;

  let obj = cbor.decode(data);

  let type = options.defaultType ? options.defaultType : MAC0Tag;
  if (obj instanceof Tagged) {
    if (obj.tag !== MAC0Tag && obj.tag !== MACTag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = obj.tag;
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
  let pMap = (!p.length) ? EMPTY_BUFFER : cbor.decode(p);
  pMap = (!pMap.size) ? EMPTY_BUFFER : pMap;
  u = (!u.size) ? EMPTY_BUFFER : u;

  // TODO validate protected header
  const alg = (pMap !== EMPTY_BUFFER) ? pMap.get(common.HeaderParameters.alg) : (u !== EMPTY_BUFFER) ? u.get(common.HeaderParameters.alg) : undefined;
  const encodedP = (!pMap.size) ? EMPTY_BUFFER : cbor.encode(pMap);
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
