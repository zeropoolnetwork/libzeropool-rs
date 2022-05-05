# libzkbob-rs-wasm
Wasm/JavaScript version of libzkbob-rs.

## Install
Bundler version:
`npm i -S libzkbob-rs-wasm-bundler`
or nodejs version:
`npm i -S libzkbob-rs-wasm-nodejs`

## Configuration

### Webpack 5
When using the bundler version, make sure that the `experiments.asyncWebAssembly` is set to `true` and there is no `import` to `require` transformation
happening before webpack has a chance to process your code. 

For example, in your `tsconfig.json` set this option so that the typescript compiler does not transform your imports
`compilerOptions.module = "es2020"`

```javascript
  experiments: {
    asyncWebAssembly: true,
  }
```

## Usage
```js
import { UserAccount, State } from 'libzkbob-rs-wasm-bundler';

const state = await State.init("any user identifier");
const account = new UserAccount(spendingKey, state);

const address = account.generateAddress();
const mergeTx = await account.createTx([{ to: address, amount: "0"}], blockchainData);

const params = Params.fromBinary(serializedParameters);
const proof = Proof.tx(params, mergeTx.public, mergeTx.secret);

```

## Development

### Build
Build both bundler and nodejs versions:
```
scripts/build
```

### Test in Headless Browsers with `wasm-pack test`
```
wasm-pack test --headless --firefox
```
