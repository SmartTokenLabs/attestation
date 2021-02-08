import {uint8tohex} from "./utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedInfo, SubjectPublicKeyInfo} from "../asn1/shemas/AttestationFramework";
import {Name} from "../asn1/shemas/InformationFramework";
import {AlgorithmIdentifierASN, Extensions} from "../asn1/shemas/AuthenticationFramework";
import {KeyPair} from "./KeyPair";

export class Attestation {
    protected version = 18; // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
    private serialNumber: any;
    // private signature:AlgorithmIdentifierASN;
    // der encoded
    protected signature:string;
    private issuer: Name;//X500Name  Optional
    private notValidBefore: any;// Optional
    private notValidAfter: any;// Optional
    //private subject: Name;  //X500Name  CN=Ethereum address     // Optional
    // der encoded
    protected subject: string;  //X500Name  CN=Ethereum address     // Optional
    protected subjectPublicKeyInfo: SubjectPublicKeyInfo;    // Optional
    // der encoded
    //protected subjectPublicKeyInfo: string;    // Optional
    protected subjectPublicKey: KeyPair;    // Optional
    private smartcontracts: any; // ASN1integers  // Optional
    private dataObject: any;
    protected riddle: Uint8Array;
    // der encoded
    // protected extensions: string;
    protected extensions: Extensions;
    private signedInfo: Uint8Array;
    constructor(){

    }
    static fromDerEncode( signedInfo: Uint8Array): Attestation {
        let decodedAttestationObj: SignedInfo = AsnParser.parse(signedInfo, SignedInfo);

        let me = new this();
        me.signedInfo = signedInfo;
        me.version = decodedAttestationObj.version.version;
        me.serialNumber = decodedAttestationObj.serialNumber;

        me.signature = decodedAttestationObj.signature.algorithm.toString();

        if (decodedAttestationObj.validity){
            me.notValidBefore = decodedAttestationObj.validity.notBefore.generalizedTime.getTime();
            me.notValidAfter = decodedAttestationObj.validity.notAfter.generalizedTime.getTime();
        }
        // TODO enable it
        let rdn = decodedAttestationObj.subject.rdnSequence;
        if (rdn && rdn[0] && rdn[0][0]){
            let obj = rdn[0][0];
            me.subject = (obj.type.toString() == "2.5.4.3" ? "CN=" : "") + obj.value;
        }
        // me.subject = decodedAttestationObj.subject.rdnSequence;
        // TODO enable it
        me.subjectPublicKeyInfo = decodedAttestationObj.subjectPublicKeyInfo;
        me.subjectPublicKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(me.subjectPublicKeyInfo.value.subjectPublicKey)));

        me.issuer = decodedAttestationObj.issuer;
        // this = attestation.issuer;

        if (decodedAttestationObj.contract){
            me.smartcontracts = decodedAttestationObj.contract;
        }

        if (decodedAttestationObj.attestsTo.extensions){
            me.extensions = decodedAttestationObj.attestsTo.extensions;
            me.riddle = new Uint8Array(me.extensions.extension.extnValue);
        } else if(decodedAttestationObj.attestsTo.dataObject) {
            // TODO parse dataObject
            //me.extensions = decodedAttestationObj.attestsTo.dataObject;
        }
        return me;
    }
    getDerEncoding(): string{
        return uint8tohex(new Uint8Array(this.signedInfo));
    }

    getRiddle(): Uint8Array{
        return this.riddle;
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
        if (this.version == null
            || this.serialNumber == null
            || this.signature == null
            || (this.extensions == null && this.dataObject == null && !this.riddle)
        ) {
            console.log("Some attest data missed");
            console.log(this.extensions);
            console.log(this.dataObject);
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
    getVersion(): number{
        return this.version;
    }

    setSubject(subject: string){
        // TODO encode correctly
        this.subject = subject;
    }
    getSubject(): string{
        return this.subject;
    }
    getSignature(): string{
        return this.signature;
    }


}
