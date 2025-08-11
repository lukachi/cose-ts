# COSE.js React Browser Example

This React application demonstrates the browser implementation of the COSE.js library. It replaces the original HTML test files with interactive React components that test various aspects of the COSE (CBOR Object Signing and Encryption) implementation.

## Features

- **Build Request Test**: Tests the complete flow of building, signing, encrypting, decrypting, and verifying a COSE request message (based on `build-request.test.ts`)
- **Sign Test**: Demonstrates COSE_Sign1 signing and verification functionality
- **Encrypt Test**: Shows COSE_Encrypt encryption and decryption capabilities
- **CBOR Test**: Tests CBOR encoding/decoding in the browser environment

## Getting Started

### Prerequisites

- Node.js (version 22 or higher)
- pnpm (recommended) or npm

### Installation

1. Navigate to the example directory:
   ```bash
   cd example
   ```

2. Install dependencies:
   ```bash
   pnpm install
   # or
   npm install
   ```

3. Start the development server:
   ```bash
   pnpm dev
   # or
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:5173`

## Project Structure

```
example/
├── src/
│   ├── components/
│   │   ├── BuildRequestTest.tsx    # Main test based on build-request.test.ts
│   │   ├── SignTest.tsx           # COSE signing test
│   │   ├── EncryptTest.tsx        # COSE encryption test
│   │   ├── CborTest.tsx           # CBOR encoding/decoding test
│   │   └── TestContainer.tsx      # Reusable test container component
│   ├── cose-utils.ts             # Utility functions from build-request.test.ts
│   ├── App.tsx                   # Main application component
│   ├── App.css                   # Application styles
│   ├── index.css                 # Global styles
│   └── main.tsx                  # Application entry point
├── package.json
├── vite.config.ts               # Vite configuration with polyfills
├── tsconfig.json               # TypeScript configuration
└── README.md
```

## Key Features

### Browser Compatibility
- Configured with necessary polyfills for Node.js modules (Buffer, crypto, stream)
- Uses Vite with React for fast development and optimized builds
- Supports modern browsers with ES2020+ features

### Test Components
Each test component provides:
- Interactive test execution
- Real-time result display
- Error handling and logging
- Step-by-step progress tracking

### COSE Implementation Testing
The Build Request Test specifically tests:
- CBOR encoding/decoding of messages
- ECDH key derivation
- COSE signing with ES256
- COSE encryption with A256GCM
- Complete round-trip verification

## Configuration

The project is configured to work with the parent COSE.js library:
- Local dependency reference to `@lukachi/cose-ts`
- Proper polyfills for browser compatibility
- TypeScript support with strict typing

## Development

To add new tests:
1. Create a new component in `src/components/`
2. Follow the pattern of existing test components
3. Use the `TestContainer` component for consistent UI
4. Add the new test to the navigation in `App.tsx`

## Building for Production

```bash
pnpm build
# or
npm run build
```

The built files will be in the `dist/` directory and can be served statically.

## Original HTML Tests Replaced

This React application replaces the following HTML test files:
- `browser-build-test.html`
- `browser-cbor-test.html`
- `browser-cose-full-test.html`
- `browser-cose-real-test.html`
- `browser-cose-test.html`
- `browser-test.html`

Each test is now implemented as a React component with better user interaction and result visualization.
