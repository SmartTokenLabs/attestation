import {base64ToUint8array} from "./utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation, SignedInfo, SubjectPublicKeyInfo} from "../asn1/shemas/AttestationFramework";
import {KeyPair} from "./KeyPair";
import {SignatureUtility} from "./SignatureUtility";
import {getUTCDate} from "pvutils";
import {Name} from "../asn1/shemas/InformationFramework";
import {AlgorithmIdentifierASN} from "../asn1/shemas/AuthenticationFramework";

export class Attestation {
    private version = 18; // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
    private serialNumber: any;
    private signature:AlgorithmIdentifierASN;
    private issuer: Name;                              //X500Name  Optional
    private notValidBefore: any;           // Optional
    private notValidAfter: any;            // Optional
    private subject: Name;  // X500Name  CN=Ethereum address     // Optional
    private subjectPublicKeyInfo: SubjectPublicKeyInfo;    // Optional
    private smartcontracts: any; // ASN1integers  // Optional
    private dataObject: any;
    private extensions: any;
    constructor(private attestation: SignedInfo) {
        this.version = attestation.version.version;
        this.serialNumber = attestation.serialNumber;
        this.signature = attestation.signature;
        // TODO stuck here
        // this.issuerSeq = ;

    }
    getDerEncoding(): Uint8Array{
        let attEncoded: Uint8Array = this.getPrehash();
        // The method returns null if the encoding is invalid
        if (attEncoded == null) {
            throw new Error("The attestation is not valid");
        }
        return attEncoded;
    }
    getPrehash(): Uint8Array{
        if (!this.checkValidity()) {
            return null;
        }
        // ASN1EncodableVector res = new ASN1EncodableVector();
        // res.add(new DERTaggedObject(true, 0, this.version));
        // res.add(this.serialNumber);
        // res.add(this.signature);
        // res.add(this.issuer == null ? new DERSequence() : this.issuer);
        // if (this.notValidAfter != null && this.notValidBefore != null) {
        //     ASN1EncodableVector date = new ASN1EncodableVector();
        //     date.add(new Time(this.notValidBefore));
        //     date.add(new Time(this.notValidAfter));
        //     res.add(new DERSequence(date));
        // } else {
        //     res.add(DERNull.INSTANCE);
        // }
        // res.add(this.subject == null ? new DERSequence() : this.subject);
        // res.add(this.subjectPublicKeyInfo == null ? DERNull.INSTANCE : this.subjectPublicKeyInfo);
        // if (this.smartcontracts != null) {
        //     res.add(this.smartcontracts);
        // }
        // if (this.extensions != null) {
        //     res.add(new DERTaggedObject(true, 3, this.extensions));
        // } else {
        //     res.add(new DERTaggedObject(true, 4, this.dataObject));
        // }
        // try {
        //     return new DERSequence(res).getEncoded();
        // } catch (IOException e) {
        //     throw new RuntimeException(e);
        // }
    }
    getNotValidBefore(){

    }
    getNotValidAfter(){

    }

    checkValidity(){
        if (this.version == null || this.serialNumber == null || this.signature == null || (this.extensions == null
            && this.dataObject == null)) {
            return false;
        }
        if (this.getNotValidBefore() != null && this.getNotValidAfter() != null) {
            let currentTime = Date.now();
            let attNotBefore = this.getNotValidBefore();
            let attNotAfter = this.getNotValidAfter();
            if (attNotBefore != null && attNotAfter != null) {
                // if (!(currentTime >= attNotBefore.getTime() && currentTime < attNotAfter.getTime())) {
                //     console.log("Attestation is no longer valid");
                //     return false;
                // }
            }
        }
        return true;
    }

}
