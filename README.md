# libzeropool-wasm
Wasm/JavaScript version of [libzeropool](https://github.com/zeropoolnetwork/libzeropool).

## Install
`yarn add libzeropool-wasm` or `npm i libzeropool-wasm -S`

## Configuration
This package uses NodeJS the `fs` API (fs.readFileSync) to load the Wasm binary.
Make sure to set up your build tools properly (e.g. using `asset/resource` type of module with webpack.)

## Usage
```js
import { deriveAddress } from 'libzeropool-wasm';

// 32 byte seed
const input = new Uint8Array(32);
const newPrivateAddress = deriveAddress(input); // 48 byte base58 encoded address
```

## Development

### Build with `wasm-pack build`

```
wasm-pack build --target nodejs
```

### Test in Headless Browsers with `wasm-pack test`

```
wasm-pack test --headless --firefox
```

### Publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```
