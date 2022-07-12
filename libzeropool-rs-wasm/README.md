# libzeropool-rs-wasm
Wasm/JavaScript version of libzeropool-rs.

## Install
Bundler version:
`npm i -S libzeropool-rs-wasm-bundler`
or nodejs version:
`npm i -S libzeropool-rs-wasm-nodejs`

## Usage
```js
import { UserAccount, State } from 'libzeropool-rs-wasm-bundler';

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
