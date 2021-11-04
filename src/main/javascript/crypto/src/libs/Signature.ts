import { KeyPair } from "./KeyPair";

export interface Signature {
    getRawSignature(): string;

    getTypeOfSignature(): string;

    /**
     * Processes any message and returns the raw bytes that are actually being signed
     * @return
     */
    processMessage(unprocessedMsg: Uint8Array): number[];

    verify(unprocessedMsg: Uint8Array, verificationKey: KeyPair): boolean;
}