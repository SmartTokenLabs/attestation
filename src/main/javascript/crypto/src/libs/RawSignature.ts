import {AbstractSignature} from "./AbstractSignature";
import {KeyPair} from "./KeyPair";
import {SignatureUtility} from "./SignatureUtility";
import {uint8toString} from "./utils";

export class RawSignature extends AbstractSignature {
    static TYPE_OF_SIGNATURE = "raw";

    public fromMessage(keys: KeyPair, unprocessedMsg: Uint8Array) {
        super.keyMessageType(keys, unprocessedMsg, RawSignature.TYPE_OF_SIGNATURE);
    }

    public fromSignature( rawSignature: string) {
        super.signatureAndType(rawSignature, RawSignature.TYPE_OF_SIGNATURE);
    }

    public processMessage( unprocessedMsg: Uint8Array): number[] {
        return Array.from(unprocessedMsg);
    }

}