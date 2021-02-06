import { CURVE_BN256 } from "./Point.js";
export function stringToHex(str) {
    var hex = '';
    for (var i = 0; i < str.length; i++) {
        hex += '' + str.charCodeAt(i).toString(16);
    }
    return hex;
}
export function hexStringToArray(str) {
    let arr = [];
    let strArr = [...str];
    if (strArr.length % 2)
        strArr.unshift('0');
    let tempStr = '';
    while (strArr.length) {
        tempStr = '';
        tempStr += strArr.shift() + strArr.shift();
        arr.push(parseInt(tempStr, 16));
    }
    return arr;
}
export function mod(a, b = CURVE_BN256.P) {
    const result = a % b;
    return result >= 0 ? result : b + result;
}
export function invert(number, modulo = CURVE_BN256.P) {
    if (number === 0n || modulo <= 0n) {
        throw new Error('invert: expected positive integers');
    }
    let [gcd, x] = egcd(mod(number, modulo), modulo);
    if (gcd !== 1n) {
        throw new Error('invert: does not exist');
    }
    return mod(x, modulo);
}
// Eucledian GCD
// https://brilliant.org/wiki/extended-euclidean-algorithm/
export function egcd(a, b) {
    let [x, y, u, v] = [0n, 1n, 1n, 0n];
    while (a !== 0n) {
        let [q, r] = [b / a, b % a];
        let [m, n] = [x - u * q, y - v * q];
        [b, a] = [a, r];
        [x, y] = [u, v];
        [u, v] = [m, n];
    }
    return [b, x, y];
}
export function uint8ToBn(uint8) {
    return bufToBn(uint8);
}
export function bufToBn(buf) {
    let hex = [];
    let u8 = Uint8Array.from(buf);
    u8.forEach(function (i) {
        var h = i.toString(16);
        if (h.length % 2) {
            h = '0' + h;
        }
        hex.push(h);
    });
    return BigInt('0x' + hex.join(''));
}
export function bnToUint8(bn) {
    return bnToBuf(bn);
}
export function bnToBuf(bn) {
    var hex = BigInt(bn).toString(16);
    if (hex.length % 2) {
        hex = '0' + hex;
    }
    var len = hex.length / 2;
    var u8 = new Uint8Array(len);
    var i = 0;
    var j = 0;
    while (i < len) {
        u8[i] = parseInt(hex.slice(j, j + 2), 16);
        i += 1;
        j += 2;
    }
    return u8;
}
export function uint8merge(list) {
    if (list.length === 1)
        return list[0];
    let out = Uint8Array.from([]);
    if (list.length === 0)
        return out;
    for (let i = 0; i < list.length; i++) {
        let temp = new Uint8Array(out.length + list[i].length);
        temp.set(out);
        temp.set(list[i], out.length);
        out = temp;
    }
    return out;
}
export function uint8arrayToBase64(bytes) {
    var binary = '';
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
export function base64ToUint8array(base64str) {
    // change base64url to base64
    base64str = base64str.split('_').join('/')
        .split('-').join('+')
        .split('.').join('=');
    let res;
    if (typeof Buffer !== 'undefined') {
        res = Uint8Array.from(Buffer.from(base64str, 'base64'));
    }
    else {
        res = Uint8Array.from(atob(base64str), c => c.charCodeAt(0));
    }
    // var asciiStr = window.atob( base64str );
    // let byteArray: number[] = [];
    // for (var i = 0; i < asciiStr.length; i++) {
    //     byteArray.push(asciiStr.charCodeAt(i));
    // }
    // return Uint8Array.from( byteArray );
    return res;
}
export function stringToArray(str) {
    var arr = [];
    for (var i = 0; i < str.length; i++) {
        arr.push(str.charCodeAt(i));
    }
    return arr;
}
export function BnPowMod(base, n, mod) {
    let res = 1n, cur = base;
    while (n > 0n) {
        if (n & 1n)
            res = (res * cur) % mod;
        cur = (cur * cur) % mod;
        n >>= 1n;
    }
    return res;
}
export function uint8tohex(uint8) {
    return Array.from(uint8).map(i => ('0' + i.toString(16)).slice(-2)).join('');
}
