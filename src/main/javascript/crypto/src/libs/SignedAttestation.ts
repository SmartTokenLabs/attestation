import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {uint8toBuffer, uint8tohex} from "./utils";
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
    private uint8data: Uint8Array;
    private attestorKeys: KeyPair;

    constructor() {}

    static fromBytes(uint8data: Uint8Array, attestorKeys: KeyPair): SignedAttestation {
        let me = new this();
        me.uint8data = uint8data;
        me.attestorKeys = attestorKeys;
        const myAttestation: MyAttestation = AsnParser.parse( uint8toBuffer( uint8data ), MyAttestation);
        me.att = new Attestation();
        me.att.fromDerEncode(myAttestation.signedInfo);

        me.signature = myAttestation.signatureValue;
        if (!me.verify()) {
            throw new Error("SignedAttestation signature is not valid");
        }
        return me;
    }

    static fromData(att: Attestation, attestorKeys: KeyPair): SignedAttestation{
        let me = new this();
        me.attestorKeys = attestorKeys;
        me.att = att;
        // TODO implement
        // me.signature = attestorKeys.signBytes(att.getPrehash());
        // me.attestationVerificationKey = attestorKeys.getPublicKeyAsHexStr();
        // if (!this.verify()) {
        //     throw new Error("The signature is not valid");
        // }
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
        return uint8tohex(new Uint8Array(this.uint8data));
    }
}
