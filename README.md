# Description

### Features
 * No dependencies.
 * Uses bigint.
 * Compiled as ES module.
 * Written in TypeScript.
 * Native JS implementations of crypto functions missing from WebCrypto.
 * Has tests! (you would be surprised how many crypto libraries have one or few tests)
 * Readable.  Too many crypto libraries are obtuse, this one strives for readability of the source code when possible.
 * Not terribly large.  ~79.2KB without any compression or minification, ~21.6KB gzipped unminified. a bundler with tree shaking and minification could probably get that down significantly

This library is built for working in a browser or other environment with access to the WebCrypto standard.  WebCrypto, unfortunately, doesn't provide Keccak256 or Secp256k1 so those are both implemented locally in this library in JavaScript.  They are both "fast enough" for most needs, but if you are going to be doing something like searching for vanity addresses you should probably use a different library.

Beyond providing access to raw secp256k1 and keccak256, this library also provides an implementation of BIP32 (HD Wallet) and BIP39 (mnemonic wallet).  The words list is currently embedded into the source code, and only English is embedded at the moment.  If there is demand for other languages and/or extracting the language out into a dynamic import that can probably be achieved.

This project is built targeting ES modules and CommonJS.  It can be loaded natively in modern browsers without bundling, but it should be bundlable without difficulty if desired.

# Usage

```bash
npm install @zoltu/ethereum-crypto
```

```typescript
import { mnemonic, secp256k1, keccak256, hdWallet, ethereum } from '@zoltu/ethereum-crypto'


/**
 * Mnemonic (BIP39)
 */

// generate a random mnemonic using WebCrypto's getRandomBytes...
const words: string[] = await mnemonic.generateRandom(128)
// ... or from entropy you supply
const words: string[] = await mnemonic.generateFromEntropy(crypto.getRandomValues(new Uint8Array(32)))

// turn a mnemonic into a seed from a space separated word list with no passphrase...
const seed: bigint = await mnemonic.toSeed('legal winner thank year wave sausage worth useful legal winner thank yellow')
// ... or turn a word array with a passphrase into a seed
const seed: bigint = await mnemonic.toSeed(['legal', 'winner', 'thank', 'year', 'wave', 'sausage', 'worth', 'useful', 'legal', 'winner', 'thank', 'yellow'], 'TREZOR')


/**
 * HD Wallet (BIP32)
 */

// generate a private key from a seed (512-bit number) and the Ethereum default derivation path...
const privateKey: bigint = await hdWallet.privateKeyFromSeed(seed as bigint)
// ... or from a byte array of your own bits and a specified derivation path
const privateKey: bigint = await hdWallet.privateKeyFromSeed(seed as Uint8Array, `m/44'/60'/0'/0/0`)


/**
 * Ethereum
 */

// sign the keccak hash of a message...
const signature: {r:bigint, s:bigint, recoveryParameter:0|1} = await ethereum.signRaw(privateKey as bigint, messageToSign as string | Uint8Array)
// ... or sign the Ethereum standard prefixed message
const signature: {r:bigint, s:bigint, recoveryParameter:0|1} = await ethereum.mutateAndSign(privateKey as bigint, messageToSign as string | Uint8Array)

// accepts a canonical method signature...
const functionSelector: number = await ethereum.functionSignatureToSelector('transfer(address,uint256)')
// ... or a verbose method signature
const functionSelector: number = await ethereum.functionSignatureToSelector('transfer(address destination, uint256 amount)')

// since Ethereum fonuders decided public keys as addresses were a bad idea
const address: Uint8Array & {length:20} = await ethereum.publicKeyToAddress(publicKey as {x:bigint, y:bigint})


/**
 * secp256k1
 */

const privateKey: bigint = await secp256k1.generatePrivateKey()

const publicKey: {x:bigint, y:bigint} = await secp256k1.privateKeyToPublicKey(privateKey as bigint)

const encodedPoint: Uint8Array & {length:65} = secp256k1.encodePoint(publicKey as {x:bigint, y:bigint})
const encodedPoint: Uint8Array & {length:33} = secp256k1.encodePointCompressed(publicKey as {x:bigint, y:bigint})
const point: {x:bigint, y:bigint} = secp256k1.decodePoint(encodedPoint as Uint8Array & {length:65})

const signature: {r:bigint, s:bigint, recoveryParameter:0|1} = await secp256k1.sign(privateKey as bigint, messageHash as bigint)

const isValid: boolean = await secp256k1.verify(publicKey as {x:bigint, y:bigint}, messageHash as bigint, signature as {r:bigint, s:bigint, recoveryParameter:0|1})


/**
 * keccak256
 */

// so simple!
const hash: bigint = await keccak256.hash(input as Uint8Array)
// ... or if you have a string to start with
const hash: bigint = await keccak256.hash(new TextEncoder().encode('The quick brown fox jumps over the lazy dog'))
```
