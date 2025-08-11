import { describe, expect, it } from "vitest";
import { randomBytes } from '@noble/hashes/utils'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'
import { sign, encrypt, type COSEHeaders, type COSESigner, type COSEOptions } from '../src'
import { p256 } from '@noble/curves/nist'
import * as cbor from 'cbor2'

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
    return Buffer.from(cbor.encode(message))
}

export const decodeCborMessage = <T>(messageBuffer: Buffer): T => {
    return cbor.decode(new Uint8Array(messageBuffer))
}

export const signMessage = async (privateKey: Uint8Array, cborMessage: Buffer, opts?: {
    unprotected?: COSEHeaders['u']
}) => {
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

    return signedCose
}

export const verifyMessage = async (compressedPublicKey: Uint8Array, signedMessage: Buffer) => {
    const point = p256.Point.fromHex(compressedPublicKey)

    const verifier = {
        key: {
            kty: 'EC2',
            crv: 'P-256',
            x: Buffer.from(point.x.toString(16).padStart(64, '0'), 'hex'),
            y: Buffer.from(point.y.toString(16).padStart(64, '0'), 'hex')
        }
    }

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

const adminPK = 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678'
const hsmPK = '0259da6479b7fdf857882613186a8d7c34f740b9f0aaa86b4875388cb7c1a4f59c'

const testAdminUserId = '550e8400-e29b-41d4-a716-446655440000'
const kid = `customer:${testAdminUserId}`
const blockstream = new Blockstream(
    Buffer.from(adminPK, 'hex'), // test admin pk
    Buffer.from(hsmPK, 'hex'), // hsm pk
)

describe("Build Request", () => {
  it("Should build request and parse it", async () => {
    const originalMessage = { 'action': 'get', 'resource': '/users' }
    
    // Log the original message
    console.log('Original message:', originalMessage)
    
    // Log CBOR encoding of original message
    const cborMsg = encodeMessageToCbor(originalMessage)
    console.log('CBOR encoded message:', cborMsg)
    console.log('CBOR decoded back:', decodeCborMessage(cborMsg))
    
    const request = await blockstream.request(
      originalMessage,
      {
        unprotected: {
          kid: Buffer.from(kid, 'utf-8')
          }
      }
    )

    console.log('Final encrypted request buffer:', request.toString('hex'))
    console.log('Final encrypted request buffer length:', request.length)
    
    // Let's also log the intermediate steps
    const signedMessage = await signMessage(
      new Uint8Array(Buffer.from(adminPK, 'hex')), 
      cborMsg,
      {
        unprotected: {
          kid: Buffer.from(kid, 'utf-8')
        }
      }
    )
    console.log('Signed message:', signedMessage.toString('hex'))
    console.log('Signed message decoded:', cbor.decode(new Uint8Array(signedMessage)))

    const sharedKey = deriveSharedKey(new Uint8Array(Buffer.from(adminPK, 'hex')), new Uint8Array(Buffer.from(hsmPK, 'hex')))
    const decryptedRequest = await encrypt.read(
      request,
      Buffer.from(sharedKey)
    )

    console.log('Decrypted request:', decryptedRequest)
    console.log('Decrypted request decoded:', cbor.decode(new Uint8Array(decryptedRequest)))

    const adminPublicKey = p256.getPublicKey(new Uint8Array(Buffer.from(adminPK, 'hex')), true)
    const verifiedRequest = await verifyMessage(
      adminPublicKey,
      decryptedRequest
    )

    console.log('Verified request:', verifiedRequest)
    console.log('Verified request decoded:', decodeCborMessage(verifiedRequest))

    expect(verifiedRequest).toBeDefined()
  })
})
