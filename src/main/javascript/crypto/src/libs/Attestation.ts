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
    private issuer: Name;//X500Name  Optional
    private notValidBefore: any;// Optional
    private notValidAfter: any;// Optional
    private subject: Name;  //X500Name  CN=Ethereum address     // Optional
    private subjectPublicKeyInfo: SubjectPublicKeyInfo;    // Optional
    private smartcontracts: any; // ASN1integers  // Optional
    private dataObject: any;
    private extensions: any;
    private signedInfo: Uint8Array;
    constructor(){

    }
    static fromDerEncode( signedInfo: Uint8Array): Attestation {
        let decodedAttestationObj: SignedInfo = AsnParser.parse(signedInfo, SignedInfo);
        let me = new this();
        me.signedInfo = signedInfo;
        me.version = decodedAttestationObj.version.version;
        me.serialNumber = decodedAttestationObj.serialNumber;
        me.signature = decodedAttestationObj.signature;
        if (decodedAttestationObj.validity){
            me.notValidBefore = decodedAttestationObj.validity.notBefore.generalizedTime.getTime();
            me.notValidAfter = decodedAttestationObj.validity.notAfter.generalizedTime.getTime();
        }
        me.subject = decodedAttestationObj.subject;
        me.subjectPublicKeyInfo = decodedAttestationObj.subjectPublicKeyInfo;
        me.issuer = decodedAttestationObj.issuer;
        // this = attestation.issuer;

        if (decodedAttestationObj.contract){
            me.smartcontracts = decodedAttestationObj.contract;
        }

        if (decodedAttestationObj.attestsTo.extensions){
            me.extensions = decodedAttestationObj.attestsTo.extensions;
        } else if(decodedAttestationObj.attestsTo.dataObject) {
            me.extensions = decodedAttestationObj.attestsTo.dataObject;
        }
        return me;
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
    setVersion(version: number){
        this.version = version;
    }

    setSubject(subject: string){
        // TODO
        // this.subject = subject;
    }

    // setSignature(signature: string){
    //     this.signature = signature;
    // }


}
