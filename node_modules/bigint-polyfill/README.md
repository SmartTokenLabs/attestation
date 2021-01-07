# BigInt polyfill

This is a thin wrapper arround the BigInt class from https://github.com/peterolson/BigInteger.js.
It has the same methods, plus convenience methods to convert to and from uint8 arrays.
Internally it uses the native BigInt type if supported by the environment. 

## Usage

```
npm install --save bigint-polyfill
```

```
const BigInt = require('bigint-polyfill');
const a = new BigInt(2n ** 63n - 1n); // in Node.js 10.4+ and supported browsers
// const a = new BigInt('9223372036854775807'); // in other environments
const b = a.divide(2n);
b.toUint8Array();
> Uint8Array [ 63, 255, 255, 255, 255, 255, 255, 255 ]

const b = BigInt.fromUint8Array(new Uint8Array([ 63, 255, 255, 255, 255, 255, 255, 255 ]));
b.toString()
> 4611686018427387903
```