import {
    getInt64Bytes,
    hashStringTo32bytesUint8,
    hashUint8To32bytesUint8,
    hexStringToArray,
    stringToArray,
    uint8merge
} from "./utils";

export class Nonce {
    static TIMESTAMP_SLACK_MS:number = 60000; // 1 minute

    ethAddressToUint8(str: string): Uint8Array {
        // TODO Ensure that the address is valid, since this will throw an exception if not
        let addr = Uint8Array.from(hexStringToArray(str.substr(2)));
        if (addr.length != 20) throw new Error('wrong address length');
        return addr;
    }

    makeNonce(senderIdentifier: string, address: string, receiverIdentifier: string,otherData: Uint8Array = new Uint8Array([]), timestampInMs: number) {
        // Hash to ensure all variable length components is encoded with constant length
        return uint8merge([
            getInt64Bytes(timestampInMs),
            hashStringTo32bytesUint8(senderIdentifier),
            this.ethAddressToUint8(address),
            hashStringTo32bytesUint8(receiverIdentifier),
            hashUint8To32bytesUint8(otherData)
        ]);
    }
/*
    validateNonce(nonce: Uint8Array, senderIdentifier: string, address: string, receiverIdentifier: string, otherData: Uint8Array = new Uint8Array([0])){
        let currentTime = Date.now();
        if (!this.validateTimestamp(getTimestamp(nonce), currentTime)) {
            return false;
        }
        if (!validateSenderIdentifier(nonce, senderIdentifier)) {
            return false;
        }
        if (!validateAddress(nonce, address)) {
            return false;
        }
        if (!validateReceiverIdentifier(nonce, receiverIdentifier)) {
            return false;
        }
        if (!validateOtherData(nonce, otherData)) {
            return false;
        }

        return true;
}
*/
}
