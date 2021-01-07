[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
![Node CI](https://github.com/juanelas/bigint-conversion/workflows/Node%20CI/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/juanelas/bigint-conversion/badge.svg?branch=master)](https://coveralls.io/github/juanelas/bigint-conversion?branch=master)

# bigint-conversion
Convert to/from non-negative integers represented with [ES-2020 native JS implementation of BigInt](https://tc39.es/ecma262/#sec-bigint-objects) from/to:

- `Buffer` (node.js) or `ArrayBuffer|TypedArray` (native js),
- hex `string`,
- utf8-encoded text `string`.

It provides a common interface for the conversions that works for both **node.js** and **native javascript**.

> Note that there is not a directly visible `TypedArray()` constructor, but a set of typed array ones: `Int8Array()`, `Uint8Array()`, `Uint8ClampedArray()`, `Int16Array()`, `Uint16Array()`, `Int32Array()`, `Uint32Array()`, `Float32Array()`, `Float64Array()`, `BigInt64Array()`, `BigUint64Array()`.

## Installation

bigint-conversion is distributed for [web browsers and/or webviews supporting BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#Browser_compatibility) as an ES6 module or an IIFE file; and for Node.js as a CJS module.

bigint-conversion can be imported to your project with `npm`:

```bash
npm install bigint-conversion
```

NPM installation defaults to the ES6 module for browsers and the CJS one for Node.js. For web browsers, you can also directly download the [IIFE bundle](https://raw.githubusercontent.com/juanelas/bigint-conversion/master/lib/index.browser.bundle.iife.js) or the [ESM bundle](https://raw.githubusercontent.com/juanelas/bigint-conversion/master/lib/index.browser.bundle.mod.js) from the repository.

Import your module as :

 - Node.js
   ```javascript
   const bigintConversion = require('bigint-conversion')
   ... // your code here
   ```
 - JavaScript native or TypeScript project
   ```javascript
   import * as bigintConversion from 'bigint-conversion'
   ... // your code here
   ```
   > BigInt is [ES-2020](https://tc39.es/ecma262/#sec-bigint-objects). In order to use it with TypeScript you should set `lib` (and probably also `target` and `module`) to `esnext` in `tsconfig.json`.
 - JavaScript native browser ES6 mod
   ```html
   <script type="module">
      import * as bigintConversion from 'lib/index.browser.bundle.mod.js'  // Use you actual path to the broser mod bundle
      ... // your code here
    </script>
   ```
 - JavaScript native browser IIFE
   ```html
   <script src="../../lib/index.browser.bundle.iife.js"></script> <!-- Use you actual path to the browser bundle -->
   <script>
     ... // your code here
   </script>
   ```

## API reference documentation

<a name="bigintToBuf"></a>

### bigintToBuf(a, [returnArrayBuffer]) ⇒ <code>ArrayBuffer</code> \| <code>Buffer</code>
Converts an arbitrary-size non-negative bigint to an ArrayBuffer or a Buffer (default for Node.js)

**Kind**: global function  
**Returns**: <code>ArrayBuffer</code> \| <code>Buffer</code> - An ArrayBuffer or a Buffer with a binary representation of the input bigint  
**Throws**:

- <code>RangeError</code> a should be a non-negative integer. Negative values are not supported


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| a | <code>bigint</code> |  |  |
| [returnArrayBuffer] | <code>boolean</code> | <code>false</code> | In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default). |

<a name="bufToBigint"></a>

### bufToBigint(buf) ⇒ <code>bigint</code>
Converts an ArrayBuffer, TypedArray or Buffer (node.js) to a bigint

**Kind**: global function  
**Returns**: <code>bigint</code> - A BigInt  

| Param | Type |
| --- | --- |
| buf | <code>ArrayBuffer</code> \| [<code>TypedArray</code>](#TypedArray) \| <code>Buffer</code> | 

<a name="bigintToHex"></a>

### bigintToHex(a) ⇒ <code>str</code>
Converts a non-negative bigint to a hexadecimal string

**Kind**: global function  
**Returns**: <code>str</code> - A hexadecimal representation of the input bigint  
**Throws**:

- <code>RangeError</code> a should be a non-negative integer. Negative values are not supported


| Param | Type |
| --- | --- |
| a | <code>bigint</code> | 

<a name="hexToBigint"></a>

### hexToBigint(hexStr) ⇒ <code>bigint</code>
Converts a hexadecimal string to a bigint

**Kind**: global function  
**Returns**: <code>bigint</code> - A BigInt  

| Param | Type |
| --- | --- |
| hexStr | <code>string</code> | 

<a name="bigintToText"></a>

### bigintToText(a) ⇒ <code>string</code>
Converts a non-negative bigint representing a binary array of utf-8 encoded text to a string of utf-8 text

**Kind**: global function  
**Returns**: <code>string</code> - A string text with utf-8 encoding  
**Throws**:

- <code>RangeError</code> a should be a non-negative integer. Negative values are not supported


| Param | Type | Description |
| --- | --- | --- |
| a | <code>bigint</code> | A non-negative bigint representing a binary array of utf-8 encoded text. |

<a name="textToBigint"></a>

### textToBigint(text) ⇒ <code>bigint</code>
Converts a utf-8 string to a bigint (from its binary representaion)

**Kind**: global function  
**Returns**: <code>bigint</code> - A bigint representing a binary array of the input utf-8 encoded text  

| Param | Type | Description |
| --- | --- | --- |
| text | <code>string</code> | A string text with utf-8 encoding |

<a name="bufToText"></a>

### bufToText(buf) ⇒ <code>string</code>
Converts an ArrayBuffer, TypedArray or Buffer (in Node.js) containing utf-8 encoded text to a string of utf-8 text

**Kind**: global function  
**Returns**: <code>string</code> - A string text with utf-8 encoding  

| Param | Type | Description |
| --- | --- | --- |
| buf | <code>ArrayBuffer</code> \| [<code>TypedArray</code>](#TypedArray) \| <code>Buffer</code> | A buffer containing utf-8 encoded text |

<a name="textToBuf"></a>

### textToBuf(str, [returnArrayBuffer]) ⇒ <code>ArrayBuffer</code> \| <code>Buffer</code>
Converts a string of utf-8 encoded text to an ArrayBuffer or a Buffer (default in Node.js)

**Kind**: global function  
**Returns**: <code>ArrayBuffer</code> \| <code>Buffer</code> - An ArrayBuffer or a Buffer containing the utf-8 encoded text  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| str | <code>string</code> |  | A string of text (with utf-8 encoding) |
| [returnArrayBuffer] | <code>boolean</code> | <code>false</code> | In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default). |

<a name="bufToHex"></a>

### bufToHex(buf) ⇒ <code>string</code>
Returns the hexadecimal representation of a buffer.

**Kind**: global function  
**Returns**: <code>string</code> - A string with a hexadecimal representation of the input buffer  

| Param | Type |
| --- | --- |
| buf | <code>ArrayBuffer</code> \| [<code>TypedArray</code>](#TypedArray) \| <code>Buffer</code> | 

<a name="hexToBuf"></a>

### hexToBuf(hexStr, [returnArrayBuffer]) ⇒ <code>ArrayBuffer</code> \| <code>Buffer</code>
Converts a hexadecimal string to a buffer

**Kind**: global function  
**Returns**: <code>ArrayBuffer</code> \| <code>Buffer</code> - An ArrayBuffer or a Buffer  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| hexStr | <code>string</code> |  | A string representing a number with hexadecimal notation |
| [returnArrayBuffer] | <code>boolean</code> | <code>false</code> | In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default). |

<a name="TypedArray"></a>

### TypedArray : <code>Int8Array</code> \| <code>Uint8Array</code> \| <code>Uint8ClampedArray</code> \| <code>Int16Array</code> \| <code>Uint16Array</code> \| <code>Int32Array</code> \| <code>Uint32Array</code> \| <code>Float32Array</code> \| <code>Float64Array</code> \| <code>BigInt64Array</code> \| <code>BigUint64Array</code>
A TypedArray object describes an array-like view of an underlying binary data buffer.

**Kind**: global typedef  

* * *