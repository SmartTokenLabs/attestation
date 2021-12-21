import {AbstractSignature} from './AbstractSignature';
import {KeyPair} from "./KeyPair";
import {ethers} from "ethers";
import {SignatureUtility} from "./SignatureUtility";
import {AttestationCrypto} from "./AttestationCrypto";
import {hexStringToArray, stringToArray, uint8tohex} from "./utils";

export class CompressedMsgSignature extends AbstractSignature {
    private static TYPE_OF_SIGNATURE = "compressed";
    private messagePrefix: string;
    private messagePostfix: string;

    public fromRawSignature(rawSignature: string) {
        this.fromRawSignatureAndPrefix(rawSignature, "", "");
    }

    public fromRawSignatureAndPrefix(rawSignature: string, messagePrefix:string, messagePostfix:string) {
        this.messagePrefix = messagePrefix;
        this.messagePostfix = messagePostfix;
        this.rawSignature = rawSignature;
    }

    public fromMessage(keys: KeyPair, unprocessedMsg: Uint8Array) {
        this.fromKeyMessagePrefix(keys, unprocessedMsg, "", "");
    }

    public fromKeyMessagePrefix(keys: KeyPair, unprocessedMsg: Uint8Array, messagePrefix:string, messagePostfix:string) {
        this.messagePrefix = messagePrefix;
        this.messagePostfix = messagePostfix;
        this.rawSignature = this.sign(keys, unprocessedMsg);
    }


    public fromSignature(signature: string) {
        this.signatureAndType(signature, CompressedMsgSignature.TYPE_OF_SIGNATURE);
    }

    protected sign(keys: KeyPair, unprocessedMsg: Uint8Array):string {
        return keys.signRawBytesWithEthereum(this.processMessage(unprocessedMsg));
    }

    public verify(unprocessedMsg: Uint8Array, verificationKey: KeyPair): boolean {
        return verificationKey.verifyBytesWithEthereum(this.processMessage(unprocessedMsg), this.rawSignature);
    }

    public processMessage( unprocessedMsg: Uint8Array): number[] {

        let hashedUnprocessedMsg: Uint8Array = AttestationCrypto.hashWithKeccak(unprocessedMsg);
        let hexEncodedHashedMsg = "0x" + uint8tohex(hashedUnprocessedMsg).toUpperCase();
        let stringMsgToSign:string =  this.messagePrefix + hexEncodedHashedMsg + this.messagePostfix;
        return stringToArray(stringMsgToSign);
    }

    public getTypeOfSignature(): string {
        return CompressedMsgSignature.TYPE_OF_SIGNATURE;
    }

}