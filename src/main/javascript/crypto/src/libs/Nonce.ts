import {
    ethAddressToUint8,
    getInt64Bytes,
    hashStringTo32bytesUint8,
    hashUint8To32bytesUint8,
    hexStringToArray,
    stringToArray,
    uint8merge, uint8ToBn, uint8tohex, uint8toString
} from "./utils";
import {AttestationCrypto} from "./AttestationCrypto";
import {SignatureUtility} from "./SignatureUtility";
import {ValidationTools} from "./ValidationTools";

export class Nonce {
    static LONG_BYTES:number = 8;

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
            Uint8Array.from(stringToArray(address)),
            hashStringTo32bytesUint8(receiverIdentifier),
            hashUint8To32bytesUint8(otherData)
        ]);
    }

    validateNonce(nonce: Uint8Array, senderIdentifier: string, address: string, receiverIdentifier: string, timestampSlack:number, otherData: Uint8Array = new Uint8Array(0)){

        if (!ValidationTools.validateTimestamp(this.getTimestamp(nonce), Date.now(), timestampSlack)) {
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

    validateSenderIdentifier(nonce: Uint8Array, senderIdentifier: string):boolean {
        if (uint8tohex(hashStringTo32bytesUint8(senderIdentifier)).toLowerCase() === uint8tohex(nonce.slice(Nonce.LONG_BYTES , Nonce.LONG_BYTES +
            AttestationCrypto.BYTES_IN_DIGEST)).toLowerCase()) return true;
        return false;
    }

    validateAddress(nonce: Uint8Array, address: string):boolean {
        if (address.toLowerCase() === uint8toString(nonce.slice(Nonce.LONG_BYTES + AttestationCrypto.BYTES_IN_DIGEST, Nonce.LONG_BYTES +
            AttestationCrypto.BYTES_IN_DIGEST + ValidationTools.ADDRESS_LENGTH_IN_BYTES)).toLowerCase()) return true;
        return false;
    }

    validateReceiverIdentifier(nonce: Uint8Array, receiverIdentifier: string):boolean {
        if (uint8tohex(hashStringTo32bytesUint8(receiverIdentifier)).toLowerCase() === uint8tohex(nonce.slice(Nonce.LONG_BYTES + AttestationCrypto.BYTES_IN_DIGEST+ ValidationTools.ADDRESS_LENGTH_IN_BYTES, Nonce.LONG_BYTES + AttestationCrypto.BYTES_IN_DIGEST * 2 + ValidationTools.ADDRESS_LENGTH_IN_BYTES)).toLowerCase()) return true;
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
