import * as cbor from 'cbor-x';
import { p256, p384, p521 } from '@noble/curves/nist';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2';
import * as jsrsasign from 'jsrsasign';
import * as common from './common.js';
import type { COSEHeaders, COSESigner, COSEVerifier, COSEOptions, AlgorithmInfo, NodeAlgorithm } from './types.js';

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tag;

export const SignTag = 98;
export const Sign1Tag = 18;

interface AlgFromTagsMap {
  [key: number]: AlgorithmInfo;
}

const AlgFromTags: AlgFromTagsMap = {};
AlgFromTags[-7] = { sign: 'ES256', digest: 'SHA-256' };
AlgFromTags[-35] = { sign: 'ES384', digest: 'SHA-384' };
AlgFromTags[-36] = { sign: 'ES512', digest: 'SHA-512' };
AlgFromTags[-37] = { sign: 'PS256', digest: 'SHA-256' };
AlgFromTags[-38] = { sign: 'PS384', digest: 'SHA-384' };
AlgFromTags[-39] = { sign: 'PS512', digest: 'SHA-512' };
AlgFromTags[-257] = { sign: 'RS256', digest: 'SHA-256' };
AlgFromTags[-258] = { sign: 'RS384', digest: 'SHA-384' };
AlgFromTags[-259] = { sign: 'RS512', digest: 'SHA-512' };

interface COSEAlgToNodeAlgMap {
  [key: string]: NodeAlgorithm;
}

const COSEAlgToNobleAlg: COSEAlgToNodeAlgMap = {
  ES256: { sign: 'p256', digest: 'sha256' },
  ES384: { sign: 'p384', digest: 'sha384' },
  ES512: { sign: 'p521', digest: 'sha512' },
  RS256: { sign: 'RSA-SHA256', digest: 'sha256' },
  RS384: { sign: 'RSA-SHA384', digest: 'sha384' },
  RS512: { sign: 'RSA-SHA512', digest: 'sha512' },
  PS256: { alg: 'pss-sha256', saltLen: 32, digest: 'sha256' },
  PS384: { alg: 'pss-sha384', saltLen: 48, digest: 'sha384' },
  PS512: { alg: 'pss-sha512', saltLen: 64, digest: 'sha512' }
};

// Helper function to get the correct hash function
function getHashFunction(digest: string): (data: Uint8Array) => Uint8Array {
  switch (digest) {
    case 'sha256':
      return sha256;
    case 'sha384':
      return sha384;
    case 'sha512':
      return sha512;
    default:
      throw new Error(`Unsupported hash algorithm: ${digest}`);
  }
}

// Helper function to get the correct curve
function getCurve(curveName: string) {
  switch (curveName) {
    case 'p256':
      return p256;
    case 'p384':
      return p384;
    case 'p521':
      return p521;
    default:
      throw new Error(`Unsupported curve: ${curveName}`);
  }
}

// Helper function for RSA signing using jsrsasign
async function rsaSign(data: Buffer, key: any, algorithm: string): Promise<Buffer> {
  try {
    // Convert COSE key format to JWK format for jsrsasign
    const jwkKey = {
      kty: 'RSA',
      n: key.n.toString('base64url'),
      e: key.e.toString('base64url'),
      d: key.d.toString('base64url'),
      p: key.p?.toString('base64url'),
      q: key.q?.toString('base64url'),
      dp: key.dp?.toString('base64url'),
      dq: key.dq?.toString('base64url'),
      qi: key.qi?.toString('base64url'),
    };

    // Create RSA private key object
    const rsaKey = jsrsasign.KEYUTIL.getKey(jwkKey);
    
    // Determine the hash algorithm
    let hashAlg: string;
    if (algorithm.includes('256')) {
      hashAlg = 'SHA256';
    } else if (algorithm.includes('384')) {
      hashAlg = 'SHA384';
    } else if (algorithm.includes('512')) {
      hashAlg = 'SHA512';
    } else {
      throw new Error(`Unsupported hash algorithm in ${algorithm}`);
    }

    // Create signature object
    let sig: jsrsasign.KJUR.crypto.Signature;
    if (algorithm.startsWith('PS')) {
      // PSS signature
      sig = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSAandMGF1` });
    } else {
      // PKCS#1 v1.5 signature
      sig = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSA` });
    }

    sig.init(rsaKey);
    sig.updateHex(data.toString('hex'));
    const signature = sig.sign();
    
    return Buffer.from(signature, 'hex');
  } catch (error) {
    throw new Error(`RSA signing failed: ${error}`);
  }
}

// Helper function for RSA verification using jsrsasign
async function rsaVerify(data: Buffer, signature: Buffer, key: any, algorithm: string): Promise<boolean> {
  try {
    // Convert COSE key format to JWK format for jsrsasign
    const jwkKey = {
      kty: 'RSA',
      n: key.n.toString('base64url'),
      e: key.e.toString('base64url'),
    };

    // Create RSA public key object
    const rsaKey = jsrsasign.KEYUTIL.getKey(jwkKey);
    
    // Determine the hash algorithm
    let hashAlg: string;
    if (algorithm.includes('256')) {
      hashAlg = 'SHA256';
    } else if (algorithm.includes('384')) {
      hashAlg = 'SHA384';
    } else if (algorithm.includes('512')) {
      hashAlg = 'SHA512';
    } else {
      throw new Error(`Unsupported hash algorithm in ${algorithm}`);
    }

    // Create signature verification object
    let sig: jsrsasign.KJUR.crypto.Signature;
    if (algorithm.startsWith('PS')) {
      // PSS verification
      sig = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSAandMGF1` });
    } else {
      // PKCS#1 v1.5 verification
      sig = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSA` });
    }

    sig.init(rsaKey);
    sig.updateHex(data.toString('hex'));
    return sig.verify(signature.toString('hex'));
  } catch (error) {
    return false;
  }
}

/**
 * Prepare payload for signing based on the specified format
 */
function preparePayloadWithOptions(payload: Buffer | any, options?: COSEOptions): Buffer {
  const format = options?.payloadFormat || 'auto-detect';
  
  switch (format) {
    case 'raw':
      // Always treat as raw bytes
      return Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
      
    case 'cbor-encoded':
      // Always CBOR encode the payload
      return cbor.encode(payload);
      
    case 'auto-detect':
    default:
      // Auto-detect: if it's a Tagged value or complex object, encode it
      if (payload instanceof Tagged || 
          (typeof payload === 'object' && !Buffer.isBuffer(payload))) {
        return cbor.encode(payload);
      }
      return Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  }
}

/**
 * Helper function to create a payload with CBOR tag(64) for typed arrays
 */
export function createTypedArrayPayload(data: Uint8Array): InstanceType<typeof Tagged> {
  return new Tagged(data, 64);
}

/**
 * Helper function to create a payload with raw bytes (no CBOR encoding)
 */
export function createBytesPayload(data: Buffer): Buffer {
  return data;
}

/**
 * Helper function to create a CBOR-encoded payload with tag(24)
 */
export function createCborPayload(data: any): InstanceType<typeof Tagged> {
  return new Tagged(cbor.encode(data), 24);
}

function doSign(SigStructure: any[], signer: COSESigner, alg: number): Buffer {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNobleAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }

  let ToBeSigned = cbor.encode(SigStructure);

  let sig: Buffer;
  if (AlgFromTags[alg].sign.startsWith('ES')) {
    // Use Noble curves for ECDSA
    const algInfo = COSEAlgToNobleAlg[AlgFromTags[alg].sign];
    const hashFunction = getHashFunction(algInfo.digest!);
    const hashedData = hashFunction(new Uint8Array(ToBeSigned));
    
    const curve = getCurve(algInfo.sign!);
    const privateKey = new Uint8Array(signer.key.d!);
    
    // Sign the hashed data
    const signature = curve.sign(hashedData, privateKey);
    
    // Convert to COSE format (r || s)
    const coordSize = curve === p256 ? 32 : curve === p384 ? 48 : 66; // P-256: 32, P-384: 48, P-521: 66
    const r = signature.r.toString(16).padStart(coordSize * 2, '0');
    const s = signature.s.toString(16).padStart(coordSize * 2, '0');
    
    sig = Buffer.concat([
      Buffer.from(r, 'hex'),
      Buffer.from(s, 'hex')
    ]);
  } else if (AlgFromTags[alg].sign.startsWith('PS') || AlgFromTags[alg].sign.startsWith('RS')) {
    // Use jsrsasign for RSA operations - now works synchronously
    const algInfo = COSEAlgToNobleAlg[AlgFromTags[alg].sign];
    try {
      // Convert COSE key format to JWK format for jsrsasign
      const jwkKey = {
        kty: 'RSA',
        n: signer.key.n!.toString('base64url'),
        e: signer.key.e!.toString('base64url'),
        d: signer.key.d!.toString('base64url'),
        p: signer.key.p?.toString('base64url'),
        q: signer.key.q?.toString('base64url'),
        dp: signer.key.dp?.toString('base64url'),
        dq: signer.key.dq?.toString('base64url'),
        qi: signer.key.qi?.toString('base64url'),
      };

      // Create RSA private key object
      const rsaKey = jsrsasign.KEYUTIL.getKey(jwkKey);
      
      // Determine the hash algorithm
      let hashAlg: string;
      const algorithm = algInfo.alg || algInfo.sign!;
      if (algorithm.includes('256')) {
        hashAlg = 'SHA256';
      } else if (algorithm.includes('384')) {
        hashAlg = 'SHA384';
      } else if (algorithm.includes('512')) {
        hashAlg = 'SHA512';
      } else {
        throw new Error(`Unsupported hash algorithm in ${algorithm}`);
      }

      // Create signature object
      let signatureObj: jsrsasign.KJUR.crypto.Signature;
      if (algorithm.startsWith('PS')) {
        // PSS signature
        signatureObj = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSAandMGF1` });
      } else {
        // PKCS#1 v1.5 signature
        signatureObj = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSA` });
      }

      signatureObj.init(rsaKey);
      signatureObj.updateHex(ToBeSigned.toString('hex'));
      const signature = signatureObj.sign();
      
      sig = Buffer.from(signature, 'hex');
    } catch (error) {
      throw new Error(`RSA signing failed: ${error}`);
    }
  } else {
    throw new Error('Unsupported algorithm: ' + AlgFromTags[alg].sign);
  }
  return sig;
}

// Async version for RSA support
export async function doSignAsync(SigStructure: any[], signer: COSESigner, alg: number): Promise<Buffer> {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNobleAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }

  let ToBeSigned = cbor.encode(SigStructure);

  let sig: Buffer;
  if (AlgFromTags[alg].sign.startsWith('ES')) {
    // Use Noble curves for ECDSA (same as sync version)
    const algInfo = COSEAlgToNobleAlg[AlgFromTags[alg].sign];
    const hashFunction = getHashFunction(algInfo.digest!);
    const hashedData = hashFunction(new Uint8Array(ToBeSigned));
    
    const curve = getCurve(algInfo.sign!);
    const privateKey = new Uint8Array(signer.key.d!);
    
    // Sign the hashed data
    const signature = curve.sign(hashedData, privateKey);
    
    // Convert to COSE format (r || s)
    const coordSize = curve === p256 ? 32 : curve === p384 ? 48 : 66; // P-256: 32, P-384: 48, P-521: 66
    const r = signature.r.toString(16).padStart(coordSize * 2, '0');
    const s = signature.s.toString(16).padStart(coordSize * 2, '0');
    
    sig = Buffer.concat([
      Buffer.from(r, 'hex'),
      Buffer.from(s, 'hex')
    ]);
  } else if (AlgFromTags[alg].sign.startsWith('PS') || AlgFromTags[alg].sign.startsWith('RS')) {
    // Use jsrsasign for RSA operations
    const algInfo = COSEAlgToNobleAlg[AlgFromTags[alg].sign];
    sig = await rsaSign(ToBeSigned, signer.key, algInfo.alg || algInfo.sign!);
  } else {
    throw new Error('Unsupported algorithm: ' + AlgFromTags[alg].sign);
  }
  return sig;
}

export function create(headers: COSEHeaders, payload: Buffer | any, signers: COSESigner[] | COSESigner, options?: COSEOptions): Promise<Buffer> {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  // Prepare the payload based on the specified format
  const processedPayload = preparePayloadWithOptions(payload, options);

  const pMap = common.TranslateHeaders(p);
  const uMap = common.TranslateHeaders(u);
  let bodyP = pMap || new Map();
  let bodyPEncoded = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
  
  if (Array.isArray(signers)) {
    if (signers.length === 0) {
      throw new Error('There has to be at least one signer');
    }
    
    // Handle multiple signers
    const signatures: any[] = [];
    
    for (const signer of signers) {
      const externalAAD = signer.externalAAD || EMPTY_BUFFER;
      let signerP = signer.p || {};
      let signerU = signer.u || {};

      // Add kid to signer headers if it exists in the key
      if (signer.key.kid && !signerP.kid && !signerU.kid) {
        signerU.kid = signer.key.kid;
      }

      const signerPMap = common.TranslateHeaders(signerP);
      const signerUMap = common.TranslateHeaders(signerU);
      const alg = signerPMap.get(common.HeaderParameters.alg);
      const signerPEncoded = (signerPMap.size === 0) ? EMPTY_BUFFER : cbor.encode(signerPMap);

      const SigStructure = [
        'Signature',
        bodyPEncoded,
        signerPEncoded,
        externalAAD,
        processedPayload
      ];

      const sig = doSign(SigStructure, signer, alg);
      signatures.push([signerPEncoded, signerUMap, sig]);
    }
    
    let encodedP: Buffer;
    if (pMap.size === 0 && options.encodep === 'empty') {
      encodedP = EMPTY_BUFFER;
    } else {
      encodedP = cbor.encode(pMap);
    }
    const signed = [encodedP, uMap, processedPayload, signatures];
    return Promise.resolve(cbor.encode(options.excludetag ? signed : new Tagged(signed, SignTag)));
  } else {
    const signer = signers;
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    const alg = pMap.get(common.HeaderParameters.alg) || uMap.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      bodyPEncoded,
      externalAAD,
      processedPayload
    ];
    const sig = doSign(SigStructure, signer, alg);
    let encodedP: Buffer;
    if (pMap.size === 0 && options.encodep === 'empty') {
      encodedP = EMPTY_BUFFER;
    } else {
      encodedP = cbor.encode(pMap);
    }
    const signed = [encodedP, uMap, processedPayload, sig];
    return Promise.resolve(cbor.encode(options.excludetag ? signed : new Tagged(signed, Sign1Tag)));
  }
}

function doVerify(SigStructure: any[], verifier: COSEVerifier, alg: number, sig: Buffer): void {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  const nobleAlg = COSEAlgToNobleAlg[AlgFromTags[alg].sign];
  if (!nobleAlg) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  const ToBeSigned = cbor.encode(SigStructure);

  if (AlgFromTags[alg].sign.startsWith('ES')) {
    // Use Noble curves for ECDSA verification
    const hashFunction = getHashFunction(nobleAlg.digest!);
    const msgHash = hashFunction(new Uint8Array(ToBeSigned));

    const curve = getCurve(nobleAlg.sign!);
    const coordSize = curve === p256 ? 32 : curve === p384 ? 48 : 66; // P-256: 32, P-384: 48, P-521: 66
    
    // Extract r and s from signature (COSE format is r || s)
    const r = sig.slice(0, coordSize);
    const s = sig.slice(coordSize);
    
    // Ensure r and s are Buffers (in case they come as arrays from cbor-x)
    const rBuffer = Buffer.isBuffer(r) ? r : Buffer.from(r);
    const sBuffer = Buffer.isBuffer(s) ? s : Buffer.from(s);
    
    // Convert public key coordinates to the right format
    const pubKeyBytes = new Uint8Array(1 + coordSize * 2); // uncompressed format
    pubKeyBytes[0] = 0x04; // uncompressed point indicator
    
    // Ensure verifier key coordinates are Buffers
    const xBuffer = Buffer.isBuffer(verifier.key.x) ? verifier.key.x : Buffer.from(verifier.key.x!);
    const yBuffer = Buffer.isBuffer(verifier.key.y) ? verifier.key.y : Buffer.from(verifier.key.y!);
    
    xBuffer.copy(pubKeyBytes, 1);
    yBuffer.copy(pubKeyBytes, 1 + coordSize);
    
    // Convert signature to Uint8Array in the format Noble expects (r || s)
    const signatureBytes = new Uint8Array(coordSize * 2);
    rBuffer.copy(signatureBytes, 0);
    sBuffer.copy(signatureBytes, coordSize);
    
    // Use verify function with raw signature bytes
    const isValid = curve.verify(signatureBytes, msgHash, pubKeyBytes);
    
    if (!isValid) {
      throw new Error('Signature mismatch');
    }
  } else if (AlgFromTags[alg].sign.startsWith('PS') || AlgFromTags[alg].sign.startsWith('RS')) {
    // Use jsrsasign for RSA verification - now works synchronously
    try {
      // Convert COSE key format to JWK format for jsrsasign
      const jwkKey = {
        kty: 'RSA',
        n: verifier.key.n!.toString('base64url'),
        e: verifier.key.e!.toString('base64url'),
      };

      // Create RSA public key object
      const rsaKey = jsrsasign.KEYUTIL.getKey(jwkKey);
      
      // Determine the hash algorithm
      let hashAlg: string;
      const algorithm = nobleAlg.alg || nobleAlg.sign!;
      if (algorithm.includes('256')) {
        hashAlg = 'SHA256';
      } else if (algorithm.includes('384')) {
        hashAlg = 'SHA384';
      } else if (algorithm.includes('512')) {
        hashAlg = 'SHA512';
      } else {
        throw new Error(`Unsupported hash algorithm in ${algorithm}`);
      }

      // Create signature verification object
      let signatureObj: jsrsasign.KJUR.crypto.Signature;
      if (algorithm.startsWith('PS')) {
        // PSS verification
        signatureObj = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSAandMGF1` });
      } else {
        // PKCS#1 v1.5 verification
        signatureObj = new jsrsasign.KJUR.crypto.Signature({ alg: `${hashAlg}withRSA` });
      }

      signatureObj.init(rsaKey);
      signatureObj.updateHex(ToBeSigned.toString('hex'));
      const isValid = signatureObj.verify(sig.toString('hex'));
      
      if (!isValid) {
        throw new Error('Signature mismatch');
      }
    } catch (error) {
      throw new Error(`RSA verification failed: ${error}`);
    }
  } else {
    throw new Error('Unsupported algorithm: ' + AlgFromTags[alg].sign);
  }
}

// Async version for RSA support
export async function doVerifyAsync(SigStructure: any[], verifier: COSEVerifier, alg: number, sig: Buffer): Promise<void> {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  const nobleAlg = COSEAlgToNobleAlg[AlgFromTags[alg].sign];
  if (!nobleAlg) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  const ToBeSigned = cbor.encode(SigStructure);

  if (AlgFromTags[alg].sign.startsWith('ES')) {
    // Use Noble curves for ECDSA verification (same as sync version)
    const hashFunction = getHashFunction(nobleAlg.digest!);
    const msgHash = hashFunction(new Uint8Array(ToBeSigned));

    const curve = getCurve(nobleAlg.sign!);
    const coordSize = curve === p256 ? 32 : curve === p384 ? 48 : 66; // P-256: 32, P-384: 48, P-521: 66
    
    // Verify signature using the Noble library
    // Convert public key coordinates to the right format
    const pubKeyBytes = new Uint8Array(1 + coordSize * 2); // uncompressed format
    pubKeyBytes[0] = 0x04; // uncompressed point indicator
    verifier.key.x!.copy(pubKeyBytes, 1);
    verifier.key.y!.copy(pubKeyBytes, 1 + coordSize);
    
    // Create signature in DER format for Noble
    const sigBytes = new Uint8Array(sig);
    const isValid = curve.verify(sigBytes, msgHash, pubKeyBytes);
    
    if (!isValid) {
      throw new Error('Signature mismatch');
    }
  } else if (AlgFromTags[alg].sign.startsWith('PS') || AlgFromTags[alg].sign.startsWith('RS')) {
    // Use jsrsasign for RSA verification
    const isValid = await rsaVerify(ToBeSigned, sig, verifier.key, nobleAlg.alg || nobleAlg.sign!);
    if (!isValid) {
      throw new Error('Signature mismatch');
    }
  } else {
    throw new Error('Unsupported algorithm: ' + AlgFromTags[alg].sign);
  }
}

function getSigner(signers: any[][], verifier: COSEVerifier): any[] | undefined {
  for (let i = 0; i < signers.length; i++) {
    const signerHeaders = signers[i][1];
    // Check if signerHeaders is a Map or needs to be decoded
    let headerMap = signerHeaders;
    if (!(signerHeaders instanceof Map)) {
      // If it's not a Map, try to treat it as an object and convert
      if (typeof signerHeaders === 'object' && signerHeaders !== null) {
        headerMap = new Map();
        if (signerHeaders.kid !== undefined) {
          headerMap.set(common.HeaderParameters.kid, signerHeaders.kid);
        }
        // Handle numeric keys as well
        Object.keys(signerHeaders).forEach(key => {
          const numKey = parseInt(key, 10);
          if (!isNaN(numKey)) {
            headerMap.set(numKey, signerHeaders[key]);
          }
        });
      }
    }
    
    if (headerMap instanceof Map && headerMap.has && headerMap.has(common.HeaderParameters.kid)) {
      const kid = headerMap.get(common.HeaderParameters.kid);
      if (kid && Buffer.isBuffer(kid) && verifier.key.kid) {
        if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
          return signers[i];
        }
      } else if (kid && typeof kid === 'string' && verifier.key.kid) {
        if (kid === verifier.key.kid) {
          return signers[i];
        }
      } else if (kid && Array.isArray(kid) && verifier.key.kid) {
        // Handle case where kid comes as array from cbor-x
        const kidBuffer = Buffer.from(kid);
        const verifierKidBuffer = Buffer.from(verifier.key.kid, 'utf8');
        if (kidBuffer.equals(verifierKidBuffer)) {
          return signers[i];
        }
      }
    }
  }
  return undefined;
}

function getCommonParameter(first: Map<number, any> | Buffer, second: Map<number, any> | Buffer, parameter: number): any {
  let result: any;
  if (first instanceof Map && first.get) {
    result = first.get(parameter);
  }
  if (!result && second instanceof Map && second.get) {
    result = second.get(parameter);
  }
  return result;
}

export async function verify(payload: Buffer, verifier: COSEVerifier, options?: COSEOptions): Promise<Buffer> {
  options = options || {};
  const obj = cbor.decode(payload);
  return verifyInternal(verifier, options, obj);
}

export function verifySync(payload: Buffer, verifier: COSEVerifier, options?: COSEOptions): Buffer {
  options = options || {};
  const obj = cbor.decode(payload);
  return verifyInternal(verifier, options, obj);
}

function verifyInternal(verifier: COSEVerifier, options: COSEOptions, obj: any): Buffer {
  options = options || {};
  let type = options.defaultType ? options.defaultType : SignTag;
  if (obj instanceof Tagged) {
    if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = obj.tag;
    obj = obj.value;
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (obj.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }

  let [p, u, plaintext, signers] = obj;

  // Ensure p and plaintext are Buffers
  if (Array.isArray(p)) {
    p = Buffer.from(p);
  }
  if (Array.isArray(plaintext)) {
    plaintext = Buffer.from(plaintext);
  }

  if (type === SignTag && !Array.isArray(signers)) {
    throw new Error('Expecting signature Array');
  }

  const pMap = (!p.length) ? EMPTY_BUFFER : cbor.decode(p);
  u = (!u.size) ? EMPTY_BUFFER : u;

  const signer = (type === SignTag ? getSigner(signers, verifier) : signers);

  if (!signer) {
    throw new Error('Failed to find signer with kid ' + verifier.key.kid);
  }

  if (type === SignTag) {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    let [signerP, , sig] = signer;
    
    // Ensure signerP and sig are Buffers
    if (Array.isArray(signerP)) {
      signerP = Buffer.from(signerP);
    }
    if (Array.isArray(sig)) {
      sig = Buffer.from(sig);
    }
    
    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    const encodedP = (!(pMap as Map<number, any>).size) ? EMPTY_BUFFER : cbor.encode(pMap);
    const signerPMap = cbor.decode(signerP);
    const alg = signerPMap.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature',
      encodedP,
      signerP,
      externalAAD,
      plaintext
    ];
    doVerify(SigStructure, verifier, alg, sig);
    return plaintext;
  } else {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

    // Ensure signer (signature) is a Buffer for Sign1 case
    let signature = signer;
    if (Array.isArray(signature)) {
      signature = Buffer.from(signature);
    }

    const alg = getCommonParameter(pMap, u, common.HeaderParameters.alg);
    const encodedP = (!(pMap as Map<number, any>).size) ? EMPTY_BUFFER : cbor.encode(pMap);
    const SigStructure = [
      'Signature1',
      encodedP,
      externalAAD,
      plaintext
    ];
    doVerify(SigStructure, verifier, alg, signature);
    return plaintext;
  }
}
