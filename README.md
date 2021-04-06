# libzeropool-wasm
Wasm/JavaScript version of [libzeropool](https://github.com/zeropoolnetwork/libzeropool).

## Install
`yarn add libzeropool-wasm` or `npm i -S libzeropool-wasm`

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
