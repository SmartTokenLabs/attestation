import {base64ToUint8array, uint8tohex} from "./utils";
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
    constructor(public signedInfo: Uint8Array) {
        // console.log('signedInfo');
        // console.log(signedInfo);
        let decodedAttestationObj: SignedInfo = AsnParser.parse(signedInfo, SignedInfo);

        // let uint8data = base64ToUint8array(asn1der);
        // const myAttestation: MyAttestation = AsnParser.parse(uint8data, MyAttestation);
        // (window as any).decodedAttestationObj = decodedAttestationObj;

        this.version = decodedAttestationObj.version.version;
        this.serialNumber = decodedAttestationObj.serialNumber;
        this.signature = decodedAttestationObj.signature;
        if (decodedAttestationObj.validity){
            this.notValidBefore = decodedAttestationObj.validity.notBefore.generalizedTime.getTime();
            this.notValidAfter = decodedAttestationObj.validity.notAfter.generalizedTime.getTime();
        }
        this.subject = decodedAttestationObj.subject;
        this.subjectPublicKeyInfo = decodedAttestationObj.subjectPublicKeyInfo;
        this.issuer = decodedAttestationObj.issuer;
        // this = attestation.issuer;

        if (decodedAttestationObj.contract){
            this.smartcontracts = decodedAttestationObj.contract;
        }

        if (decodedAttestationObj.attestsTo.extensions){
            this.extensions = decodedAttestationObj.attestsTo.extensions;
        } else if(decodedAttestationObj.attestsTo.dataObject) {
            this.extensions = decodedAttestationObj.attestsTo.dataObject;
        }
    }
    getDerEncoding(): string{
        return uint8tohex(new Uint8Array(this.signedInfo));
    }

    getNotValidBefore(): number{
        return this.notValidBefore;
    }
    getNotValidAfter(): number{
        return this.notValidAfter;
    }

    getSubjectPublicKeyInfo(){
        return this.subjectPublicKeyInfo;
    }

    checkValidity(){
        if (this.version == null || this.serialNumber == null || this.signature == null || (this.extensions == null
            && this.dataObject == null)) {
            return false;
        }
        let currentTime = Date.now();
        let attNotBefore = this.getNotValidBefore();
        let attNotAfter = this.getNotValidAfter();
        if ( attNotBefore && attNotAfter && !(currentTime >= attNotBefore && currentTime < attNotAfter)) {
            console.log("Attestation is no longer valid");
            return false;
        }
        return true;
    }

    getExtensions(){
        return this.extensions;
    }

}
