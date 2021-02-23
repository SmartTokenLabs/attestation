import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {base64ToUint8array, uint8toBuffer, uint8tohex} from "./utils";
import {SignatureUtility} from "./SignatureUtility";
import {Attestation} from "./Attestation";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {ASNEncodable} from "./ASNEncodable";

export class SignedAttestation implements ASNEncodable, Verifiable, Validateable {
    signature: any;
    publicKey: any;
    att: Attestation;
    commitment: Uint8Array;
    // constructor(asn1der: string, private keys: KeyPair) {
    constructor(
        private uint8data: Uint8Array,
        private attestorKey: KeyPair
    ) {
        const myAttestation: MyAttestation = AsnParser.parse( uint8toBuffer( this.uint8data ), MyAttestation);
        this.att = new Attestation();
        this.att.fromDerEncode(myAttestation.signedInfo);

        this.signature = myAttestation.signatureValue;
        if (!this.verify()) {
            throw new Error("SignedAttestation signature is not valid");
        }
    }

    verify(){
        try {
            let publKey = SignatureUtility.recoverPublicKeyFromMessageSignature(this.att.getDerEncoding(), new Uint8Array(this.signature));
            console.log('publKey');
            console.log(publKey);
            console.log(this.attestorKey.getPublicKeyAsHexStr());
            // return SignatureUtility.verify(this.att.getDerEncoding(), uint8tohex(new Uint8Array(this.signature)), this.attestorKey);
        } catch (e) {
            return false;
        }
    }

    getCommitment() {
        return this.att.getCommitment();
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
