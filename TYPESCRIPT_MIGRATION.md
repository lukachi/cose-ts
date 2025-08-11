# COSE TypeScript Migration

This document describes the migration of the COSE (CBOR Object Signing and Encryption) library from JavaScript to TypeScript.

## Migration Summary

The following files have been successfully migrated from JavaScript to TypeScript:

### Core Files
- `src/common.js` → `src/common.ts` - Common utilities and header translation functions
- `src/mac.js` → `src/mac.ts` - Message Authentication Code functionality  
- `src/sign.js` → `src/sign.ts` - Digital signature functionality
- `src/encrypt.js` → `src/encrypt.ts` - Encryption and decryption functionality
- `src/index.js` → `src/index.ts` - Main entry point

### New TypeScript Files
- `src/types.ts` - Type definitions for COSE data structures
- `src/external-types.d.ts` - Type declarations for external packages
- `src/example.ts` - Usage examples with TypeScript types

## Key Changes

### 1. Type Safety
- Added comprehensive type definitions for all COSE data structures
- Proper typing for headers, keys, recipients, signers, and options
- Type-safe function parameters and return values

### 2. Enhanced API
- Exported TypeScript interfaces for better IDE support
- Type-safe imports and exports throughout the codebase
- Proper typing for async/await patterns

### 3. External Dependencies
- Added type declarations for packages without TypeScript support:
  - `aes-cbc-mac`
  - `node-hkdf-sync` 
  - `node-rsa`
  - `elliptic`

### 4. Build System
- TypeScript compilation with strict type checking
- Generates both ES modules and UMD bundles
- Source maps and declaration files included

## Usage Examples

```typescript
import * as cose from '@lukachi/cose-ts';
import type { COSEHeaders, COSEOptions } from '@lukachi/cose-ts';

// Type-safe header creation
const headers: COSEHeaders = {
  p: { alg: 'HS256' },
  u: { kid: 'my-key-id' }
};

// Create a MAC with full type safety
const macData = await cose.mac.create(
  headers,
  Buffer.from('payload'),
  { key: Buffer.from('secret') }
);
```

## Benefits of TypeScript Migration

1. **Type Safety**: Compile-time error checking prevents common mistakes
2. **Better IDE Support**: IntelliSense, auto-completion, and refactoring
3. **Enhanced Documentation**: Types serve as living documentation
4. **Maintainability**: Easier to understand and modify the codebase
5. **Developer Experience**: Better tooling and debugging support

## Build and Development

```bash
# Type checking
pnpm typecheck

# Build the library
pnpm build

# Development with hot reload
pnpm dev
```

The TypeScript migration maintains 100% compatibility with the original JavaScript API while adding comprehensive type safety and improved developer experience.
