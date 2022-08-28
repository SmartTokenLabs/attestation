import { Hmac } from "crypto";
import { AttestationCrypto } from "./AttestationCrypto";
import { UnpredictableNumberBundle } from "./UnpredictableNumberBundle";
import { stringToArray, uint8arrayToBase64 } from "./utils";

export const DEFAULT_VALIDITY_IN_MS: bigint = BigInt(3600 * 1000);
export const BYTES_IN_UN: number = 16;
export const BYTES_IN_SEED: number = AttestationCrypto.BYTES_IN_DIGEST;
export const STATIC_KEY_STRING: string = "UnpredictableNumberTool";

export function hashContext(unhashedContext: Uint8Array): string {
    let key: Uint8Array = Uint8Array.from(stringToArray(STATIC_KEY_STRING));
    const hmac: Hmac = require('crypto').createHmac('sha3-256', key);
    hmac.update(unhashedContext);
    const digest: Buffer = hmac.digest();
    const result = digest.slice(0, BYTES_IN_SEED*8);
    return uint8arrayToBase64(result);
}

export interface IUnpredictableNumberTool {
    get domain(): string;
    get unpredictableNumberBundle(): UnpredictableNumberBundle;
    getUnpredictableNumberBundle(context: Uint8Array): UnpredictableNumberBundle;
    validateUnpredictableNumber(un: string, randomness:Uint8Array, expirationInMs: bigint, context?:Uint8Array): boolean;
}