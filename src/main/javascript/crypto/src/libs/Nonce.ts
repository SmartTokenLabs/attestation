import {
    ethAddressToUint8,
    getInt64Bytes,
    hashStringTo32bytesUint8,
    hashUint8To32bytesUint8,
    hexStringToArray,
    stringToArray,
    uint8merge, uint8ToBn, uint8tohex
} from "./utils";
import {AttestationCrypto} from "./AttestationCrypto";
import {SignatureUtility} from "./SignatureUtility";

export class Nonce {
    // TODO change to 1 minute
    static TIMESTAMP_SLACK_MS:number = 6000000; // 100 minute
    static LONG_BYTES:number = 8;
    static ADDRESS_BYTES:number = 20;

    static async makeNonce(senderIdentifier: string, address: string = "", receiverIdentifier: string,otherData: Uint8Array = new Uint8Array([]), timestampInMs: number = 0) {
        // Hash to ensure all variable length components is encoded with constant length
        if (!address) {
            address = await SignatureUtility.connectMetamaskAndGetAddress();
        }

        if (!timestampInMs) {
            timestampInMs = Date.now();
        }

        return uint8merge([
            getInt64Bytes(timestampInMs),
            hashStringTo32bytesUint8(senderIdentifier),
            ethAddressToUint8(address),
            hashStringTo32bytesUint8(receiverIdentifier),
            hashUint8To32bytesUint8(otherData)
        ]);
    }

    validateNonce(nonce: Uint8Array, senderIdentifier: string, address: string, receiverIdentifier: string, otherData: Uint8Array = new Uint8Array(0)){

        if (!this.validateTimestamp(this.getTimestamp(nonce), Date.now())) {
            console.log('timestamp check failed');
            return false;
        }
        if (!this.validateSenderIdentifier(nonce, senderIdentifier)) {
            console.log('validateSenderIdentifier check failed');
            return false;
        }
        if (!this.validateAddress(nonce, address)) {
            console.log('validateAddress check failed');
            return false;
        }
        if (!this.validateReceiverIdentifier(nonce, receiverIdentifier)) {
            console.log('validateReceiverIdentifier check failed');
            return false;
        }

        return this.validateOtherData(nonce, otherData);

    }

    validateTimestamp(nonceTimestamp: number, timeToCompare: number): boolean {
        if (nonceTimestamp > timeToCompare + Nonce.TIMESTAMP_SLACK_MS) {
            return false;
        }
        if (nonceTimestamp < timeToCompare - Nonce.TIMESTAMP_SLACK_MS) {
            return false;
        }
        return true;
    }

    validateSenderIdentifier(nonce: Uint8Array, senderIdentifier: string):boolean {
        if (uint8tohex(hashStringTo32bytesUint8(senderIdentifier)).toLowerCase() === uint8tohex(nonce.slice(Nonce.LONG_BYTES , Nonce.LONG_BYTES +
            AttestationCrypto.BYTES_IN_DIGEST)).toLowerCase()) return true;
        return false;
    }

    validateAddress(nonce: Uint8Array, address: string):boolean {
        if (uint8tohex(ethAddressToUint8(address)).toLowerCase() === uint8tohex(nonce.slice(Nonce.LONG_BYTES + AttestationCrypto.BYTES_IN_DIGEST, Nonce.LONG_BYTES +
            AttestationCrypto.BYTES_IN_DIGEST + Nonce.ADDRESS_BYTES)).toLowerCase()) return true;
        return false;
    }

    validateReceiverIdentifier(nonce: Uint8Array, receiverIdentifier: string):boolean {
        if (uint8tohex(hashStringTo32bytesUint8(receiverIdentifier)).toLowerCase() === uint8tohex(nonce.slice(Nonce.LONG_BYTES + AttestationCrypto.BYTES_IN_DIGEST+ Nonce.ADDRESS_BYTES, Nonce.LONG_BYTES + AttestationCrypto.BYTES_IN_DIGEST * 2 + Nonce.ADDRESS_BYTES)).toLowerCase()) return true;
        return false;
    }

    validateOtherData(nonce: Uint8Array, otherData: Uint8Array):boolean {
        if (uint8tohex(hashUint8To32bytesUint8(otherData)).toLowerCase() === uint8tohex(nonce.slice(-1 * AttestationCrypto.BYTES_IN_DIGEST )).toLowerCase()) return true;
        return false;
    }

    getTimestamp(nonce: Uint8Array): number {
        let time = nonce.slice(0,8);
        let bn = uint8ToBn(time);
        if (bn > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('timestamp value bigger than MAX_SAFE_INTEGER');
        return Number(bn);
    }

}
