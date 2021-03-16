import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {uint8toBuffer, uint8tohex} from "./utils";
import {SignatureUtility} from "./SignatureUtility";
import {Attestation} from "./Attestation";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {ASNEncodable} from "./ASNEncodable";
import {Asn1Der} from "./DerUtility";

export class SignedIdentityAttestation implements ASNEncodable, Verifiable, Validateable {
    private signature: any;
    private att: Attestation;
    private commitment: Uint8Array;
    private uint8data: Uint8Array;
    private attestorKeys: KeyPair;
    static ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

    constructor() {}

    static fromBytes(uint8data: Uint8Array, attestorKeys: KeyPair): SignedIdentityAttestation {
        let me = new this();
        me.uint8data = uint8data;
        me.attestorKeys = attestorKeys;
        const myAttestation: MyAttestation = AsnParser.parse( uint8toBuffer( uint8data ), MyAttestation);
        me.att = new Attestation();
        me.att.fromDerEncode(myAttestation.signedInfo);

        me.signature = myAttestation.signatureValue;
        if (!me.verify()) {
            throw new Error("SignedIdentityAttestation signature is not valid");
        }
        return me;
    }

    static fromData(att: Attestation, attestationSigningKey: KeyPair): SignedIdentityAttestation{
        let me = new this();
        me.attestorKeys = attestationSigningKey;
        me.att = att;
        me.att.setSigningAlgorithm(SignedIdentityAttestation.ECDSA_WITH_SHA256);
        // me.signature = SignatureUtility.signDeterministicSHA256(me.att.getPrehash(), attestationSigningKey);

        // TODO implement
        // me.constructorCheck(attestationSigningKey);
        return me;
    }

    verify(){
        try {
            // let publKey = SignatureUtility.recoverPublicKeyFromMessageSignature(this.att.getDerEncoding(), new Uint8Array(this.signature));
            // console.log('publKey');
            // console.log(publKey);
            // console.log(this.attestorKey.getPublicKeyAsHexStr());
            return SignatureUtility.verify(this.att.getDerEncoding(), uint8tohex(new Uint8Array(this.signature)), this.attestorKeys);
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
        if (this.uint8data && this.uint8data.length){
            return uint8tohex(new Uint8Array(this.uint8data));
        } else {
            return this.constructSignedAttestation();
        }

    }

    constructSignedAttestation(){

        let rawAtt: Uint8Array = this.att.getPrehash();
        let res: string = uint8tohex(rawAtt)
            + Asn1Der.encode('OBJECT_ID', this.att.getSigningAlgorithm())
            + Asn1Der.encode('BIT_STRING', this.signature);

        return Asn1Der.encode('SEQUENCE_30', res);
    }

}
