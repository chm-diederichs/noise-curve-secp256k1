# noise-curve-secp

`secp256k1` elliptic curve operations for use with [`noise-handshake`](https://github.com/chm-diederichs/noise-handshake)

## Usage
```js
const curve = require('noise-curve-secp256k1')
const Noise = require('noise-handshake')

const handshake = new Noise(pattern, initiator, staticKeyPair, { curve })
```

## API

#### constants

`DHLEN` = 32
`PKLEN` = 64
`SKLEN` = 32
`ALG` = 'secp256k1'

#### `generateKeyPair([privKey])`

Generate a new keypair, optionally pass in a preexisting `privKey`. Return value is of the form:

```
{
  publicKey,
  secretKey
}
```

#### `dh(pk, lsk)`

Perform DH between `pk` and `lsk` and return the result.
