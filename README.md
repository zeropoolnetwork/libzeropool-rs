# libzeropool-wasm
Wasm/JavaScript version of [libzeropool](https://github.com/zeropoolnetwork/libzeropool).

## Install
`yarn add libzeropool-wasm` or `npm i -S libzeropool-wasm`

## Configuration

### Webpack 5
Make sure that the `experiments.asyncWebAssembly` is set to `true` and there is no `import` to `require` transformation
happening before webpack has a chance to process you code. 

For example, in your `tsconfig.json` set this option so that the typescript compiler does not transform your imports
`compilerOptions.module = "es2020"`

```javascript
  experiments: {
    asyncWebAssembly: true,
  }
```

## Usage
```js
import { deriveAddress } from 'libzeropool-wasm';

// 32 byte seed
const input = new Uint8Array(32);
const newPrivateAddress = deriveAddress(input); // 48 byte base58 encoded address
```

## Development

### Build
```
scripts/build
```

### Test in Headless Browsers with `wasm-pack test`

```
wasm-pack test --headless --firefox
```
