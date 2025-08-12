# @lukachi/cose-ts

A modern TypeScript implementation of [COSE (CBOR Object Signing and Encryption)](https://tools.ietf.org/html/rfc8152) as defined in [RFC 8152](https://tools.ietf.org/html/rfc8152).

## Features

- 🔐 **Complete COSE implementation** - Support for signing, MAC, and encryption operations
- 🌐 **Browser and Node.js compatible** - Works in both environments with proper polyfills
- 🎯 **TypeScript first** - Fully typed API with comprehensive type definitions
- 🛡️ **Modern cryptography** - Built on [@noble](https://github.com/paulmillr/noble) cryptographic libraries
- 🧪 **Well tested** - Comprehensive test suite with Vitest
- 📦 **Multiple formats** - ESM, UMD, and CommonJS support

## Installation

```bash
npm install @lukachi/cose-ts
```

## Quick Start

### Signing (COSE_Sign1)

```typescript
import { sign } from '@lukachi/cose-ts';

// Create a signed message
const payload = Buffer.from('Hello, COSE!');
const headers = {
  p: { alg: 'ES256' },
  u: { kid: 'my-key-id' }
};

const signer = {
  key: {
    kty: 'EC2',
    crv: 'P-256',
    d: Buffer.from('private-key-bytes', 'hex'),
    x: Buffer.from('public-key-x-coordinate', 'hex'),
    y: Buffer.from('public-key-y-coordinate', 'hex')
  }
};

const signedMessage = await sign.create(headers, payload, signer);

// Verify the signature
const verifier = {
  key: {
    kty: 'EC2',
    crv: 'P-256',
    x: Buffer.from('public-key-x-coordinate', 'hex'),
    y: Buffer.from('public-key-y-coordinate', 'hex')
  }
};

const verifiedPayload = await sign.verify(signedMessage, verifier);
```

### Message Authentication Code (COSE_Mac)

```typescript
import { mac } from '@lukachi/cose-ts';

// Create a MAC
const payload = Buffer.from('Important message!');
const headers = {
  p: { alg: 'HS256' },
  u: { kid: 'shared-secret-id' }
};

const recipient = {
  key: Buffer.from('shared-secret-key', 'hex')
};

const macMessage = await mac.create(headers, payload, recipient);

// Verify the MAC
const verifiedPayload = await mac.read(macMessage, recipient.key);
```

### Encryption (COSE_Encrypt)

```typescript
import { encrypt } from '@lukachi/cose-ts';

// Encrypt a message
const plaintext = Buffer.from('Secret message!');
const headers = {
  p: { alg: 'A256GCM' },
  u: { kid: 'encryption-key-id' }
};

const recipient = {
  key: Buffer.from('encryption-key', 'hex')
};

const encryptedMessage = await encrypt.create(headers, plaintext, recipient);

// Decrypt the message
const decryptedPayload = await encrypt.read(encryptedMessage, recipient.key);
```

## Supported Algorithms

### Signing Algorithms
- **ES256** - ECDSA using P-256 curve and SHA-256
- **ES384** - ECDSA using P-384 curve and SHA-384  
- **ES512** - ECDSA using P-521 curve and SHA-512
- **PS256** - RSASSA-PSS using SHA-256
- **PS384** - RSASSA-PSS using SHA-384
- **PS512** - RSASSA-PSS using SHA-512

### MAC Algorithms
- **HS256** - HMAC using SHA-256
- **HS384** - HMAC using SHA-384
- **HS512** - HMAC using SHA-512

### Encryption Algorithms
- **A128GCM** - AES-128 in Galois/Counter Mode
- **A192GCM** - AES-192 in Galois/Counter Mode
- **A256GCM** - AES-256 in Galois/Counter Mode

## Development

### Prerequisites
- Node.js 22 or higher
- pnpm (recommended) or npm

### Setup

```bash
# Clone the repository
git clone https://github.com/lukachi/cose-ts.git
cd cose-ts

# Install dependencies
pnpm install

# Run tests
pnpm test

# Build the library
pnpm build

# Run the example application
cd example
pnpm install
pnpm dev
```

### Project Structure

```
src/
├── index.ts          # Main exports
├── types.ts          # TypeScript type definitions
├── common.ts         # Common utilities and constants
├── sign.ts           # COSE_Sign1 implementation
├── mac.ts            # COSE_Mac implementation
├── encrypt.ts        # COSE_Encrypt implementation
└── cbor-utils.ts     # CBOR encoding/decoding utilities

tests/                # Comprehensive test suite
example/              # React browser example application
```

## Browser Support

This library works in modern browsers with proper polyfills. The example application demonstrates browser usage with Vite providing the necessary polyfills for Node.js APIs.

## API Documentation

For detailed API documentation and advanced usage examples, see the [example application](./example) which includes interactive demonstrations of all major features.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Make sure to:

1. Add tests for new features
2. Update documentation as needed
3. Follow the existing code style
4. Ensure all tests pass

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Standards

- [RFC 8152 - CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
- [RFC 7049 - Concise Binary Object Representation (CBOR)](https://tools.ietf.org/html/rfc7049)
