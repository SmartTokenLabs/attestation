import { KeyPair } from "./KeyPair";

export interface Signature {
    getRawSignature(): string;

    getTypeOfSignature(): string;

    verify(unprocessedMsg: Uint8Array, verificationKey: KeyPair): boolean;
}