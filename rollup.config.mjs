import resolve  from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import wasm     from '@rollup/plugin-wasm';

export default [
  {
    input:  'src/app.js',
    output: {
      file:   'dist/app.bundle.js',
      format: 'es',
    },
    plugins: [
      resolve({ browser: true }),
      commonjs(),
    ]
  },
  {
    input:  'src/worker-entry.js',           // ← wherever your worker entry really lives
    output: {
      file:                 'dist/worker.bundle.js',
      format:               'esm',
      inlineDynamicImports: true,            // ← this + the wasm plugin inlines the .wasm
    },
    plugins: [
      resolve({ browser: true, preferBuiltins: false }),
      commonjs({
        ignore: ['fs','path']
      }),
      wasm({ inline: true }),
    ]
  }
];

