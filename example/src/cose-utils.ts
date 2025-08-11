import { randomBytes } from '@noble/hashes/utils'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { sign, encrypt, cborUtils, type COSEHeaders, type COSESigner, type COSEOptions } from '@lukachi/cose-ts'
import { p256 } from '@noble/curves/nist'

export class Blockstream {
    private privateKey: Uint8Array
    private hsmPublicKey: Uint8Array

    constructor(privateKey: Uint8Array, hsmPublicKey: Uint8Array) {
        this.privateKey = new Uint8Array(privateKey)
        this.hsmPublicKey = new Uint8Array(hsmPublicKey)
    }

    public async request(
        jsonMessage: object,
        opts?: {
            unprotected?: COSEHeaders['u']
            options?: COSEOptions
        }
    ) {
        const cborMsg = encodeMessageToCbor(jsonMessage)

        const signedMessage = await signMessage(this.privateKey, cborMsg, opts)

        const iv = randomBytes(12)

        // For ECDH: HSM will use its private key + our public key
        // We use our private key + HSM's public key
        // This creates the same shared secret
        // NOTE: HSM currently uses raw x-coordinate, not HKDF
        const sharedKey = deriveSharedKey(this.privateKey, this.hsmPublicKey)

        const encryptedMessage = await encryptMessage(
            Buffer.from(sharedKey),
            signedMessage,
            {
                options: {
                    randomSource: () => Buffer.from(iv)
                },
                ...opts
            }
        )

        return encryptedMessage
    }

    public async parse<T>(encryptedMessage: Uint8Array): Promise<{
        msg_id: string
        timestamp: number,
        payload: T
    }> {
        // IMPORTANT: HSM uses HKDF for response encryption (but not for request decryption)
        // This is inconsistent, but we need to match their implementation
        const sharedKey = deriveSharedKey(this.privateKey, this.hsmPublicKey)

        const decryptedMessage = await decryptMessage(sharedKey, Buffer.from(encryptedMessage))

        const buf = await verifyMessage(this.hsmPublicKey, decryptedMessage)

        const decodedMessage = decodeCborMessage<{
            msg_id: string
            timestamp: number
            payload: Uint8Array
        }>(buf)

        const decodedPayload = decodeCborMessage(Buffer.from(decodedMessage.payload))

        return {
            msg_id: decodedMessage.msg_id,
            timestamp: decodedMessage.timestamp,
            payload: decodedPayload as T
        }
    }
}

/**
 * Derive shared AES key using ECDH (matching HSM implementation)
 * 
 * IMPORTANT: The HSM currently uses the raw x-coordinate as the key,
 * without HKDF. This should be changed in production to use proper KDF.
 */
export const deriveSharedKey = (
    privateKey: Uint8Array,
    hsmPublicKey: Uint8Array,
    opts?: { isUseHkdf?: boolean }
): Uint8Array => {
    if (privateKey.length !== 32) {
        throw new Error('Private key must be 32 bytes long')
    }

    if (hsmPublicKey.length !== 33) {
        throw new Error('HSM public key must be 33 bytes long')
    }

    // Perform ECDH to get shared secret
    const sharedPoint = p256.getSharedSecret(privateKey, hsmPublicKey)

    // Extract x-coordinate (skip the first byte which is the compression flag)
    // The HSM uses only the x-coordinate of the shared point
    const sharedSecret = sharedPoint.slice(1, 33)

    if (opts?.isUseHkdf) {
        // Use HKDF to derive AES-256 key from shared secret (more secure)
        const salt = new Uint8Array(32) // Zero salt
        const info = Buffer.from('AES-256-GCM', 'utf-8')
        const aesKey = hkdf(sha256, sharedSecret, salt, info, 32)
        return aesKey
    }

    // HSM currently uses raw x-coordinate as key (NOT using HKDF)
    // This matches the HSM's current implementation in ecs.c
    return sharedSecret
}

export const encodeMessageToCbor = (message: object): Buffer => {
    console.log('=== CBOR ENCODING DEBUG ===');
    console.log('Environment info:', cborUtils.getEnvironmentInfo());
    console.log('Input message:', message);
    console.log('Input message stringified:', JSON.stringify(message, null, 2));
    
    const encoded = cborUtils.encode(message);
    console.log('Encoded result type:', typeof encoded);
    console.log('Encoded result constructor:', encoded.constructor.name);
    console.log('Encoded result length:', encoded.length);
    console.log('Encoded bytes (first 20):', Array.from(encoded.slice(0, 20)));
    console.log('Encoded bytes (all):', Array.from(encoded));
    console.log('Encoded hex:', Buffer.from(encoded).toString('hex'));
    
    return Buffer.from(encoded);
}

export const decodeCborMessage = <T>(messageBuffer: Buffer): T => {
    console.log('=== CBOR DECODING DEBUG ===');
    console.log('Environment info:', cborUtils.getEnvironmentInfo());
    console.log('Input buffer type:', typeof messageBuffer);
    console.log('Input buffer constructor:', messageBuffer.constructor.name);
    console.log('Input buffer length:', messageBuffer.length);
    console.log('Input buffer hex:', messageBuffer.toString('hex'));
    console.log('Input buffer bytes:', Array.from(messageBuffer));
    
    const decoded = cborUtils.decode<T>(new Uint8Array(messageBuffer));
    console.log('Decoded result:', decoded);
    console.log('Decoded result stringified:', JSON.stringify(decoded, null, 2));
    return decoded;
}

export const signMessage = async (privateKey: Uint8Array, cborMessage: Buffer, opts?: {
    unprotected?: COSEHeaders['u']
}) => {
    console.log('=== SIGN MESSAGE DEBUG ===');
    console.log('Input cborMessage type:', typeof cborMessage);
    console.log('Input cborMessage constructor:', cborMessage.constructor.name);
    console.log('Input cborMessage length:', cborMessage.length);
    console.log('Input cborMessage hex:', cborMessage.toString('hex'));
    
    if (privateKey.length !== 32) {
        throw new Error('Private key must be 32 bytes long')
    }

    const point = p256.Point.fromHex(p256.getPublicKey(privateKey, true))

    const signer: COSESigner = {
        key: {
            kty: 'EC2',
            crv: 'P-256',
            d: Buffer.from(privateKey),
            x: Buffer.from(point.x.toString(16).padStart(64, '0'), 'hex'),
            y: Buffer.from(point.y.toString(16).padStart(64, '0'), 'hex')
        }
    }

    const signedCose = await sign.create(
        {
            p: { alg: 'ES256' },
            u: opts?.unprotected
        },
        cborMessage,
        signer
    )

    console.log('Signed COSE result type:', typeof signedCose);
    console.log('Signed COSE result constructor:', signedCose.constructor.name);
    console.log('Signed COSE result length:', signedCose.length);
    console.log('Signed COSE result hex:', signedCose.toString('hex'));

    return signedCose
}

export const verifyMessage = async (compressedPublicKey: Uint8Array, signedMessage: Buffer) => {
    console.log('=== VERIFY MESSAGE DEBUG ===');
    console.log('Input compressedPublicKey type:', typeof compressedPublicKey);
    console.log('Input compressedPublicKey constructor:', compressedPublicKey.constructor.name);
    console.log('Input signedMessage type:', typeof signedMessage);
    console.log('Input signedMessage constructor:', signedMessage.constructor.name);
    
    const point = p256.Point.fromHex(compressedPublicKey)

    const x = Buffer.from(point.x.toString(16).padStart(64, '0'), 'hex');
    const y = Buffer.from(point.y.toString(16).padStart(64, '0'), 'hex');
    
    console.log('Created x type:', typeof x);
    console.log('Created x constructor:', x.constructor.name);
    console.log('Created x isBuffer:', Buffer.isBuffer(x));
    console.log('Created y type:', typeof y);
    console.log('Created y constructor:', y.constructor.name);
    console.log('Created y isBuffer:', Buffer.isBuffer(y));

    const verifier = {
        key: {
            kty: 'EC2',
            crv: 'P-256',
            x: x,
            y: y
        }
    }

    console.log('About to call sign.verify...');
    return sign.verify(signedMessage, verifier)
}

export const encryptMessage = async (compressedPublicKey: Buffer, message: Uint8Array, opts?: {
    unprotected?: COSEHeaders['u']
    options?: COSEOptions
}) => {
    if (compressedPublicKey.length > 33) {
        throw new Error('Compressed public key must be 32-33 bytes long')
    }

    const pk = compressedPublicKey.length === 32 ? compressedPublicKey : compressedPublicKey.slice(1, 33)

    return await encrypt.create(
        {
            p: { alg: 'A256GCM' },
            u: opts?.unprotected,
        },
        Buffer.from(message),
        {
            key: Buffer.from(pk),
        },
        opts?.options
    )
}

export const decryptMessage = async (compressedPublicKey: Uint8Array, encryptedMessage: Buffer) => {
    if (compressedPublicKey.length > 33) {
        throw new Error('Compressed public key must be 32-33 bytes long')
    }

    const pk = compressedPublicKey.length === 32 ? compressedPublicKey : compressedPublicKey.slice(1, 33)

    return await encrypt.read(encryptedMessage, Buffer.from(pk))
}

// Test constants
export const adminPK = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678'
export const hsmPK = '0259da6479b7fdf857882613186a8d7c34f740b9f0aaa86b4875388cb7c1a4f59c'

export const testAdminUserId = '550e8400-e29b-41d4-a716-446655440000'
export const kid = `customer:${testAdminUserId}`

export const blockstream = new Blockstream(
    Buffer.from(adminPK, 'hex'), // test admin pk
    Buffer.from(hsmPK, 'hex'), // hsm pk
)
