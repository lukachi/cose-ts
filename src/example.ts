/**
 * Example usage of the COSE TypeScript library
 * This example demonstrates basic usage of the library with proper TypeScript types
 */

import * as cose from './index.js';
import type { COSEHeaders, COSEOptions } from './types.js';

// Example of creating a MAC (Message Authentication Code)
export async function createMacExample(): Promise<Buffer> {
  const headers: COSEHeaders = {
    p: { alg: 'HS256' },
    u: {}
  };
  
  const payload = Buffer.from('Hello, COSE TypeScript!');
  const key = Buffer.from('supersecretkey');
  const recipients = { key };
  const options: COSEOptions = {};
  
  return await cose.mac.create(headers, payload, recipients, undefined, options);
}

// Example of verifying a MAC
export async function verifyMacExample(macData: Buffer, key: Buffer): Promise<Buffer> {
  return await cose.mac.read(macData, key);
}

// Example of creating a signature  
export function createSignatureExample(): Promise<Buffer> {
  const headers: COSEHeaders = {
    p: { alg: 'ES256' },
    u: {}
  };
  
  const payload = Buffer.from('Hello, COSE TypeScript!');
  
  // This is a mock signer - in real usage you'd have actual key material
  const signer = {
    key: {
      kty: 'EC2',
      crv: 'P-256',
      x: Buffer.alloc(32),
      y: Buffer.alloc(32),
      d: Buffer.alloc(32)
    }
  };
  
  return cose.sign.create(headers, payload, signer);
}

// Example function to demonstrate type safety
export function demonstrateTypeSafety(): void {
  // TypeScript will catch errors like this:
  // const invalidHeaders: COSEHeaders = { invalid: 'property' }; // Error!
  
  // But this is valid:
  const validHeaders: COSEHeaders = {
    p: { alg: 'HS256' },
    u: { kid: 'my-key-id' }
  };
  
  console.log('Valid headers created:', validHeaders);
}
