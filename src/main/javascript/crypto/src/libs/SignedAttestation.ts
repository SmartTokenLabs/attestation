import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "./../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {base64ToUint8array} from "./utils";
import {SignatureUtility} from "./SignatureUtility";
import {Attestation} from "./Attestation";

export class SignedAttestation {
    signature: any;
    publicKey: any;
    att: Attestation;
    // constructor(asn1der: string, private keys: KeyPair) {
    constructor(asn1der: string) {
        let uint8data = base64ToUint8array(asn1der);
        const myAttestation: MyAttestation = AsnParser.parse(uint8data, MyAttestation);
        console.log("myAttestation:", myAttestation);
        console.log("myAttestation.issuer:", myAttestation);
        this.att = new Attestation(myAttestation.signedInfo);
        this.signature = myAttestation.signatureValue;
        // this.publicKey = signingPublicKey;
        // if (!this.verify()) {
        //     throw new Error("The signature is not valid");
        // }
    }

    verify(){
        try {
            // return SignatureUtility.verify(this.att.getDerEncoding(), this.signature, this.keys);
        } catch (e) {
            return false;
        }
    }

}
