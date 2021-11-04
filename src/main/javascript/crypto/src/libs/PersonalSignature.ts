import {AbstractSignature} from "./AbstractSignature";
import {KeyPair} from "./KeyPair";
import {SignatureUtility} from "./SignatureUtility";
import {uint8toString} from "./utils";

export class PersonalSignature extends AbstractSignature {
    static TYPE_OF_SIGNATURE = "personal";

    public fromMessage(keys: KeyPair, unprocessedMsg: Uint8Array) {
        super.keyMessageType(keys, unprocessedMsg, PersonalSignature.TYPE_OF_SIGNATURE);
    }

    public fromSignature( rawSignature: string) {
        super.signatureAndType(rawSignature, PersonalSignature.TYPE_OF_SIGNATURE);
    }

    public processMessage( unprocessedMsg: Uint8Array): number[] {
        return SignatureUtility.convertToPersonalEthMessage(uint8toString(unprocessedMsg));
    }

}