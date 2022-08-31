import {base64ToUint8array, bnToUint8, hexStringToBase64Url, isDomainValid, logger, stringToArray, uint8tohex, uint8toString} from "./utils";
import {UnpredictableNumberBundle} from "./UnpredictableNumberBundle";
import {DEBUGLEVEL} from "../config";
import { BYTES_IN_SEED, hashContext, IUnpredictableNumberTool } from './IUnpredictableNumberTool';
import { TextEncoder } from 'util';
import { KeyPair } from './KeyPair';

export class UNSignature implements IUnpredictableNumberTool {

    private readonly _domain: string;
    private readonly validityInMs: bigint;
    private readonly key: KeyPair;

    constructor(key: KeyPair, domain: string, validityInMs: bigint) {
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
      
    private getUnpredictableNumber(randomness: Uint8Array, expirationInMs: bigint, context?: Uint8Array): string {
        let rawUN = this.getRawUN(randomness, expirationInMs, context);
        let signature = this.key.signRawBytesWithEthereum(rawUN);
        // Let the UN be the signature
        return hexStringToBase64Url(signature);
    }

    private getRawUN(randomness: Uint8Array, expirationInMs: bigint, context?: Uint8Array): number[] {
        let textEncoder = new TextEncoder();
        let size = 8 + BYTES_IN_SEED + textEncoder.encode(this._domain).length;
        if (context !== undefined) {
            size += BYTES_IN_SEED;
        }
        let rawUnBuf: Uint8Array = new Uint8Array(size);
        let pointer = 0;
        // Ensure that the expiration time is encoded using 8 bytes
        rawUnBuf.set(bnToUint8(expirationInMs), pointer+(8-(bnToUint8(expirationInMs).length)));
        pointer += 8;
        rawUnBuf.set(randomness, pointer);
        pointer += BYTES_IN_SEED;
        if (context !== undefined) {
            rawUnBuf.set(stringToArray(hashContext(context)), pointer);
            pointer += BYTES_IN_SEED;
        }
        let encodedDomain = textEncoder.encode(this._domain);
        rawUnBuf.set(encodedDomain, pointer);
        return stringToArray(uint8toString(rawUnBuf));
    }
    
    validateUnpredictableNumber(un: string, randomness: Uint8Array, expirationInMs: bigint, context?: Uint8Array): boolean {
      if (BigInt(Date.now()) > expirationInMs) {
          logger(DEBUGLEVEL.LOW, 'Unpredictable number has expired');
          return false;
      }
      if (!this.key.verifyBytesWithEthereum(this.getRawUN(randomness, expirationInMs, context), uint8tohex(base64ToUint8array(un)))) {
        logger(DEBUGLEVEL.LOW, 'The unpredictable number is computed incorrectly. Either wrong key or wrong domain');
        return false;
      }
      return true;
  }
  
}
