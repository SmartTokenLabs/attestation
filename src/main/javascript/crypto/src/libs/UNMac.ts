import {Hmac} from 'crypto';
import {bnToUint8, base64ToUint8array, isDomainValid, logger, uint8arrayToBase64, base64toBase64Url} from "./utils";
import {UnpredictableNumberBundle} from "./UnpredictableNumberBundle";
import {DEBUGLEVEL} from "../config";
import { BYTES_IN_SEED, BYTES_IN_UN, hashContext, IUnpredictableNumberTool } from './IUnpredictableNumberTool';
import { TextEncoder } from 'util';

export class UNMac implements IUnpredictableNumberTool {

    private readonly _domain: string;
    private readonly validityInMs: bigint;
    private readonly key: Uint8Array;

    constructor(key: Uint8Array, domain: string, validityInMs: bigint) {
        if (!isDomainValid(domain)) {
        throw Error('Domain is not a valid domain');
        }
        this.key = key;
        this._domain = domain;
        this.validityInMs = validityInMs;
    }

    get domain(): string {
        return this._domain;
    }

    get unpredictableNumberBundle(): UnpredictableNumberBundle {
        return this.getUnpredictableNumberBundle();
    }

    getUnpredictableNumberBundle(context?: Uint8Array): UnpredictableNumberBundle {
        const expiration: bigint = BigInt(Date.now()) + this.validityInMs;
        const randomness = require('secure-random').randomUint8Array(BYTES_IN_SEED);
        let unpredictableNumber = this.getUnpredictableNumber(randomness, expiration, context);
        return new UnpredictableNumberBundle(unpredictableNumber, randomness, this._domain, expiration);
    }

    private getUnpredictableNumber(randomness: Uint8Array, expirationInMs: bigint, context: Uint8Array|undefined, unSize: number = BYTES_IN_UN): string {
        const hmac: Hmac = require('crypto').createHmac('sha3-256', this.key);
        // We encode this as a long of 8 bytes
        let byteTime = new Uint8Array(8);
        byteTime.set(bnToUint8(expirationInMs), 8-bnToUint8(expirationInMs).length);
        hmac.update(byteTime);
        hmac.update(randomness);
        // if (context !== undefined) {
        if (typeof context !== "undefined") {
            hmac.update(hashContext(context));
        }
        let encodedDomain = new TextEncoder().encode(this._domain);
        hmac.update(encodedDomain);
        const digest: Buffer = hmac.digest();
        const result = digest.slice(0, unSize);
        return base64toBase64Url(uint8arrayToBase64(result));
   }

    validateUnpredictableNumber(un: string, randomness:Uint8Array, expirationInMs: bigint, context?:Uint8Array): boolean {
        if ( BigInt(Date.now()) > expirationInMs) {
            logger(DEBUGLEVEL.LOW, 'Unpredictable number has expired');
            return false;
        }
        const expectedNumber = this.getUnpredictableNumber(randomness, expirationInMs, context, base64ToUint8array(un).length);
        if (expectedNumber !== un) {
            logger(DEBUGLEVEL.LOW, 'The unpredictable number is computed incorrectly. Either wrong key or wrong domain');
            return false;
        }
        return true;
    }
  
}