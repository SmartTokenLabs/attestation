/**
 * A TypedArray object describes an array-like view of an underlying binary data buffer.
 * @typedef {Int8Array|Uint8Array|Uint8ClampedArray|Int16Array|Uint16Array|Int32Array|Uint32Array|Float32Array|Float64Array|BigInt64Array|BigUint64Array} TypedArray
 */

/**
 * Converts an arbitrary-size non-negative bigint to an ArrayBuffer or a Buffer (default for Node.js)
 *
 * @param {bigint} a
 * @param {boolean} [returnArrayBuffer = false] In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default).
 *
 * @returns {ArrayBuffer|Buffer} An ArrayBuffer or a Buffer with a binary representation of the input bigint
 *
 * @throws {RangeError} a should be a non-negative integer. Negative values are not supported
 */
function bigintToBuf (a, returnArrayBuffer = false) {
  if (a < 0) throw RangeError('a should be a non-negative integer. Negative values are not supported')
  return hexToBuf(bigintToHex(a), returnArrayBuffer)
}

/**
 * Converts an ArrayBuffer, TypedArray or Buffer (node.js) to a bigint
 *
 * @param {ArrayBuffer|TypedArray|Buffer} buf
 *
 * @returns {bigint} A BigInt
 */
function bufToBigint (buf) {
  // return BigInt('0x' + bufToHex(buf))
  let bits = 8n
  if (ArrayBuffer.isView(buf)) bits = BigInt(buf.BYTES_PER_ELEMENT * 8)
  else buf = new Uint8Array(buf)

  let ret = 0n
  for (const i of buf.values()) {
    const bi = BigInt(i)
    ret = (ret << bits) + bi
  }
  return ret
}

/**
 * Converts a non-negative bigint to a hexadecimal string
 *
 * @param {bigint} a
 *
 * @returns {str} A hexadecimal representation of the input bigint
 *
 * @throws {RangeError} a should be a non-negative integer. Negative values are not supported
 */
function bigintToHex (a) {
  if (a < 0) throw RangeError('a should be a non-negative integer. Negative values are not supported')
  return a.toString(16)
}

/**
 * Converts a hexadecimal string to a bigint
 *
 * @param {string} hexStr
 *
 * @returns {bigint} A BigInt
 */
function hexToBigint (hexStr) {
  return BigInt('0x' + hexStr)
}

/**
 * Converts a non-negative bigint representing a binary array of utf-8 encoded text to a string of utf-8 text
 *
 * @param {bigint} a A non-negative bigint representing a binary array of utf-8 encoded text.
 *
 * @returns {string} A string text with utf-8 encoding
 *
 * @throws {RangeError} a should be a non-negative integer. Negative values are not supported
 */
function bigintToText (a) {
  if (a < 0) throw RangeError('a should be a non-negative integer. Negative values are not supported')
  return bufToText(hexToBuf(a.toString(16)))
}

/**
 * Converts a utf-8 string to a bigint (from its binary representaion)
 *
 * @param {string} text A string text with utf-8 encoding
 *
 * @returns {bigint} A bigint representing a binary array of the input utf-8 encoded text
 */
function textToBigint (text) {
  return hexToBigint(bufToHex(textToBuf(text)))
}

/**
 *Converts an ArrayBuffer, TypedArray or Buffer (in Node.js) containing utf-8 encoded text to a string of utf-8 text
 *
 * @param {ArrayBuffer|TypedArray|Buffer} buf A buffer containing utf-8 encoded text
 *
 * @returns {string} A string text with utf-8 encoding
 */
function bufToText (buf) {
  return new TextDecoder().decode(new Uint8Array(buf))
}

/**
 * Converts a string of utf-8 encoded text to an ArrayBuffer or a Buffer (default in Node.js)
 *
 * @param {string} str A string of text (with utf-8 encoding)
 * @param {boolean} [returnArrayBuffer = false] In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default).
 *
 * @returns {ArrayBuffer|Buffer} An ArrayBuffer or a Buffer containing the utf-8 encoded text
 */
function textToBuf (str, returnArrayBuffer = false) {
  return new TextEncoder().encode(str).buffer
}

/**
 * Returns the hexadecimal representation of a buffer.
 *
 * @param {ArrayBuffer|TypedArray|Buffer} buf
 *
 * @returns {string} A string with a hexadecimal representation of the input buffer
 */
function bufToHex (buf) {
  /* eslint-disable no-lone-blocks */
  {
    let s = ''
    const h = '0123456789abcdef'
    if (ArrayBuffer.isView(buf)) buf = new Uint8Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength))
    else buf = new Uint8Array(buf)
    buf.forEach((v) => {
      s += h[v >> 4] + h[v & 15]
    })
    return s
  }
  /* eslint-enable no-lone-blocks */
}

/**
 * Converts a hexadecimal string to a buffer
 *
 * @param {string} hexStr A string representing a number with hexadecimal notation
 * @param {boolean} [returnArrayBuffer = false] In Node JS forces the output to be an ArrayBuffer instead of a Buffer (default).
 *
 * @returns {ArrayBuffer|Buffer} An ArrayBuffer or a Buffer
 */
function hexToBuf (hexStr, returnArrayBuffer = false) {
  hexStr = !(hexStr.length % 2) ? hexStr : '0' + hexStr
  /* eslint-disable no-lone-blocks */
  {
    return Uint8Array.from(hexStr.trimLeft('0x').match(/[\da-f]{2}/gi).map((h) => {
      return parseInt(h, 16)
    })).buffer
  }
  /* eslint-enable no-lone-blocks */
}

export { bigintToBuf, bigintToHex, bigintToText, bufToBigint, bufToHex, bufToText, hexToBigint, hexToBuf, textToBigint, textToBuf }
