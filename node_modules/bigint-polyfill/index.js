const nativeBigInt = (typeof global !== 'undefined') && global.BigInt || (typeof window !== 'undefined') && window.BigInt;
const supportsNative = typeof nativeBigInt === 'function';
const _BigInt = require('big-integer');

const nativeFunction = function (operator, a) {
    switch (operator) {
      // Arithmetic operators
      case 'add': return (b) => new BigInt(a + b);
      case 'subtract': return (b) => new BigInt(a - b);
      case 'multiply': return (b) => new BigInt(a * b);
      case 'divide': return (b) => new BigInt(a / b);
      case 'remainder': return (b) => new BigInt(a % b);
      case 'pow': return (b) => new BigInt(a ** b);
      // Bitwise shift operators
      case 'shiftLeft': return (b) => new BigInt(a << b);
      case 'shiftRight': return (b) => new BigInt(a >> b);
      // Binary bitwise operators
      case 'and': return (b) => new BigInt(a & b);
      case 'or': return (b) => new BigInt(a | b);
      case 'xor': return (b) => new BigInt(a ^ b);
      // Relational operators
      case 'lt': return (b) => a < b;
      case 'gt': return (b) => a > b;
      case 'leq': return (b) => a <= b;
      case 'geq': return (b) => a >= b;
      case 'eq': return (b) => a === b;
      case 'neq': return (b) => a !== b;
      // Unary operators
      case 'negate': return () => new BigInt(- a);
      case 'not': return () => new BigInt(~ a);
      case 'next': return () => new BigInt(++a);
      case 'prev': return () => new BigInt(--a);
    }
    return undefined;
};

/**
 * A proxy for BigInt that supports both native and polyfill implementations.
 * Also includes convenience functions for conversion to and from uint8 arrays
 * with both big and little endian byte order.
 * 
 * Examples:
 *     const biNative = new BigInt(2n ** 63n - 1n));
 *     biNative.toUint8Array()
 * 
 *     const biNonNative = new BigInt('9223372036854775807');
 *     biNonNative.toUint8Array()
 */
class BigInt {
    constructor(value) {
        if (typeof value === 'bigint') {
            this.value = value;
        } else if (value instanceof BigInt) {
            return value; 
        } else {
            this.value = new _BigInt(value);
        }
        // Proxy method calls to _BigInt if possible
        return new Proxy(this, {
            get(obj, field) {
                if (field in obj) return obj[field];
                if (typeof obj.value === 'bigint') return nativeFunction(field, obj.value);
                if (typeof obj.value !== 'bigint' && field in obj.value) return obj.value[field].bind(obj.value);
                return undefined;
            }
        });
    }

    valueOf() {
        if (typeof this.value === 'bigint') {
            return this.value;
        } else {
            throw new Error('Cannot implicitly cast polyfilled BigInt into number')
        }
    }

    equals(b) {
        if (typeof this.value === 'bigint') {
            return this.value === b.value;
        } else if (b instanceof BigInt) {
            if (typeof b.value === 'bigint') {
                return this.value.equals(new _BigInt(b.toString()));
            } else {
                return this.value.equals(new _BigInt(b.value));
            } 
        } else {
            return this.value.equals(new _BigInt(b));
        }
    }

    toString() {
        return this.value.toString();
    }

    _toUint8ArrayNative(littleEndian = false, elements = 8) {
        const arr = new ArrayBuffer(elements);
        const view = new DataView(arr);
        view.setBigUint64(0, this.value, littleEndian);
        return new Uint8Array(arr);
    }

    _toUint8Array(littleEndian = false, elements = 8) {
        const arr = new ArrayBuffer(elements);
        const uint8arr = new Uint8Array(arr);
        const intarr = this.value.toArray(2**8).value;
        if (littleEndian) uint8arr.set(intarr.reverse(), 0);
        else uint8arr.set(intarr, elements - intarr.length);
        return uint8arr;
    }

    toUint8Array(littleEndian = false, elements = 8) {
        if (typeof this.value === 'bigint') {
            return this._toUint8ArrayNative(littleEndian, elements);
        } else {
            return this._toUint8Array(littleEndian, elements);
        }
    }

    /**
     * Get BigInt from a uint8 array in specified endianess.
     * Uses native BigInt if the environment supports it and detectSupport is true.
     * 
     * @param {Uint8Array} uint8arr
     * @param {boolean} littleEndian use little endian byte order, default is false
     * @param {boolean} detectSupport auto-detect support for native BigInt, default is true
     */
    static fromUint8Array(uint8arr, littleEndian = false, detectSupport = true) {
        if (supportsNative && detectSupport) {
            const view = new DataView(uint8arr.buffer);
            return new BigInt(view.getBigUint64(0, littleEndian));
        }
        let array;
        if (littleEndian) {
            array = Array.from(uint8arr).reverse();
        } else {
            array = Array.from(uint8arr);
        }
        return new BigInt(_BigInt.fromArray(array, 2**8));
    }
}

module.exports = BigInt;
