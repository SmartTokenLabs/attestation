export class AttestableObject {
    protected encoded: string;
    protected commitment: Uint8Array;
    constructor() {
    }
    public getDerEncoding(): string {
        return this.encoded;
    }

    public getCommitment(): Uint8Array {
        return this.commitment;
    }
}
