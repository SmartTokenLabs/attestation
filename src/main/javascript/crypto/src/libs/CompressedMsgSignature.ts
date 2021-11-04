import {AbstractSignature} from './AbstractSignature';
import {KeyPair} from "./KeyPair";
import {ethers} from "ethers";
import {SignatureUtility} from "./SignatureUtility";

export class CompressedMsgSignature extends AbstractSignature {
    private static TYPE_OF_SIGNATURE = "compressed";

    public fromMessage(keys: KeyPair, unprocessedMsg: Uint8Array) {
        this.keyMessageType(keys, unprocessedMsg, CompressedMsgSignature.TYPE_OF_SIGNATURE);
    }

    public fromSignature(signature: string) {
        this.signatureAndType(signature, CompressedMsgSignature.TYPE_OF_SIGNATURE);
    }

    public processMessage( unprocessedMsg: Uint8Array): number[] {
        return SignatureUtility.convertToPersonalEthMessage(ethers.utils.keccak256(Array.from(unprocessedMsg)).substring(2));
    }

}