
const BigInt = require('./index.js');
const assert = require('assert');

function test(value, littleEndian = false, detectNativeSupport = true) {
    const bi = new BigInt(value);
    const uint8arr2 = bi.toUint8Array(littleEndian);
    const bi2 = BigInt.fromUint8Array(uint8arr2, littleEndian, detectNativeSupport);
    assert(bi.equals(bi2));
}

function testAllArtihmetic(a, b) {
    const results = [];
    for (const op of ['add', 'subtract', 'multiply', 'divide', 'remainder', 'pow', 'shiftLeft', 'shiftRight', 'and', 'or', 'xor', 'lt', 'gt', 'leq', 'geq', 'eq', 'neq']) {
        results.push(a[op](b));
    }
    for (const op of ['negate', 'not', 'next', 'prev']) {
        results.push(a[op]());
    }
    return results;
}

describe('BigInt', function() {
    it('should convert bigint to uint8array and back', function() {
        const number = 2n ** 63n - 1n;
        test(number, false);
        test(number, true);
        test(number.toString(), false, false);
        test(number.toString(), true, false);
        test(number.toString(), false);
        test(number.toString(), true);
    });
    it('should compare values of the same type', function() {
        const number = 2n ** 63n - 1n;
        const a = new BigInt(number.toString());
        const b = new BigInt(number.toString());
        assert(a.equals(b));
        assert(b.equals(a));
    });
    
    it('convert to and from uint8array', function() {
        const number = 2n ** 63n - 2n;
        const a = new BigInt(number);
        const b = a.divide(2n);
        assert.deepEqual(b.toUint8Array(), [ 63, 255, 255, 255, 255, 255, 255, 255 ]);

        const c = BigInt.fromUint8Array(new Uint8Array([ 63, 255, 255, 255, 255, 255, 255, 255 ]));
        assert.equal(c, 4611686018427387903n);
        const d = c.multiply(2n);
        assert.equal(d.toString(), number.toString());
    });
    
    it('perform artihmetic functions', function() {
        const number = 2n ** 63n - 1n;
        const a1 = new BigInt(number);
        const a2 = new BigInt(number.toString());
        const b1 = 2n;
        const b2 = 2;
        const r1 = testAllArtihmetic(a1, b1);
        const r2 = testAllArtihmetic(a2, b2);
        assert.deepEqual(r1.map(a => a.toString()), r2.map(a => a.toString()));
    });
});
