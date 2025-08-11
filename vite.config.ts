import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

const __dirname = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [
    nodePolyfills({
      // Enable polyfills for specific globals and modules
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      // Enable polyfills for specific modules
      protocolImports: true,
    }),
  ],
  build: {
    emptyOutDir: false,
    sourcemap: true,
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'blockstream-sdk',
      // the proper extensions will be added
      fileName: 'index',
    },
    rollupOptions: {
      // Externalize deps that shouldn't be bundled into your library
      external: [], // Remove crypto and stream from external since we're polyfilling them
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      //   external: ['vue'],
      output: {
        // Provide global variables to use in the UMD build
        globals: {
          // No longer need to externalize these
        },
      },
    },
  },
  define: {
    global: 'globalThis',
  },
  resolve: {
    alias: {
      // Ensure Node.js modules are polyfilled for browser
      crypto: 'crypto-browserify',
      stream: 'stream-browserify',
      buffer: 'buffer',
    },
  },
})
