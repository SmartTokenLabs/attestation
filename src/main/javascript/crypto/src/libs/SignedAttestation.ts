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
    // constructor(asn1der: string, private keys: KeyPair) {
    constructor(
        private asn1der: string,
        private attestorKey: KeyPair
    ) {
        this.uint8data = base64ToUint8array(asn1der);
        const myAttestation: MyAttestation = AsnParser.parse(this.uint8data, MyAttestation);
        // console.log("myAttestation:", myAttestation);
        this.att = new Attestation(myAttestation.signedInfo);
        this.signature = myAttestation.signatureValue;
        // this.publicKey = signingPublicKey;
        if (!this.verify()) {
            throw new Error("SignedAttestation signature is not valid");
        }
    }

    verify(){
        try {
            return SignatureUtility.verifyArrayBuf(this.att.getDerEncoding(), uint8tohex(new Uint8Array(this.signature)), this.attestorKey);
        } catch (e) {
            return false;
        }
    }

    checkValidity(){
        return this.getUnsignedAttestation().checkValidity();
    }

    getUnsignedAttestation(): Attestation{
        return this.att;
    }

    getDerEncoding(): Uint8Array{
        return this.uint8data;
    }
}
