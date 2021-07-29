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
import { UserAccount, State } from 'libzeropool-wasm';

const state = await State.init("any user identifier");
const account = new UserAccount(secretKey, state);

const address = account.generateAddress();
const mergeTx = await account.createTx([{ to: address, amount: "0"}], blockchainData);

const params = Params.fromBinary(serializedParameters);
const proof = Proof.tx(params, mergeTx.public, mergeTx.secret);

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
