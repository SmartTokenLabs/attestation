import {Signature} from "./Signature";
import {KeyPair} from "./KeyPair";
import {hexStringToArray, uint8tohex} from "./utils";

export abstract class AbstractSignature implements Signature {
    private type: string;
    private rawSignature: string;

    public keyMessageType(keys: KeyPair, unprocessedMessage: Uint8Array, type:string) {
        this.type = type;
        this.rawSignature = this.sign(keys, unprocessedMessage);
    }

    public signatureAndType(rawSignature: string, type: string) {
        this.type = type;
        this.rawSignature = rawSignature;
    }

    protected sign(keys: KeyPair, unprocessedMessage: Uint8Array): string {
        return keys.signRawBytesWithEthereum(this.processMessage(unprocessedMessage));
    }

    public getRawSignature(): string {
        return this.rawSignature;
    }

    public getTypeOfSignature(): string {
        return this.type;
    }

    public abstract processMessage(unprocessedMsg: Uint8Array): number[];

    public verify(unprocessedMsg: Uint8Array, verificationKey: KeyPair): boolean {
        return verificationKey.verifyBytesWithEthereum(this.processMessage(unprocessedMsg), this.rawSignature);
    }

}