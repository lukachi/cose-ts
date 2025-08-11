import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const __dirname = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
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
      external: ['crypto', 'stream'],
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      //   external: ['vue'],
      output: {
        // Provide global variables to use in the UMD build
        globals: {
          // buffer: 'Buffer',
          crypto: 'crypto',
          stream: 'stream',
        },
      },
    },
  },
})
