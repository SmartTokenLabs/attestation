import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "./../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {base64ToUint8array, uint8tohex} from "./utils";
import {SignatureUtility} from "./SignatureUtility";
import {Attestation} from "./Attestation";

export class SignedAttestation {
    signature: any;
    publicKey: any;
    att: Attestation;
    uint8data: Uint8Array;
    commitment: Uint8Array;
    // constructor(asn1der: string, private keys: KeyPair) {
    constructor(
        private asn1der: string,
        private attestorKey: KeyPair
    ) {
        this.uint8data = base64ToUint8array(asn1der);
        const myAttestation: MyAttestation = AsnParser.parse(this.uint8data, MyAttestation);
        this.att =  Attestation.fromDerEncode(myAttestation.signedInfo);
        this.signature = myAttestation.signatureValue;
        if (!this.verify()) {
            throw new Error("SignedAttestation signature is not valid");
        }
    }

    verify(){
        try {
            return SignatureUtility.verify(this.att.getDerEncoding(), uint8tohex(new Uint8Array(this.signature)), this.attestorKey);
        } catch (e) {
            return false;
        }
    }

    getCommitment() {
        return this.att.getRiddle();
    }

    checkValidity(){
        return this.getUnsignedAttestation().checkValidity();
    }

    getUnsignedAttestation(): Attestation{
        return this.att;
    }

    getDerEncoding(): string{
        return uint8tohex(new Uint8Array(this.uint8data));
    }
}
