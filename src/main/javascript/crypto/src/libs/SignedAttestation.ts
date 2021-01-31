import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "./../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {base64ToUint8array, hexStringToArray, uint8tohex} from "./utils";
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
        this.att =  Attestation.fromDerEncode(myAttestation.signedInfo);
        this.signature = myAttestation.signatureValue;
        console.log('this.signature');
        console.log(this.signature);
        // this.publicKey = signingPublicKey;
        if (!this.verify()) {
            throw new Error("SignedAttestation signature is not valid");
        }
    }

    verify(){
        // console.log('uint8tohex(new Uint8Array(this.signature))');
        // console.log(uint8tohex(new Uint8Array(this.signature)));
        // console.log(this.attestorKey.getPublicKeyAsHexStr());
        // console.log(this.att.getDerEncoding());
        try {
            return SignatureUtility.verify(this.att.getDerEncoding(), uint8tohex(new Uint8Array(this.signature)), this.attestorKey);
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

    getDerEncoding(): string{
        return uint8tohex(new Uint8Array(this.uint8data));
    }
}
