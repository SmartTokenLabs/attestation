import {uint8toBuffer, uint8tohex} from "./utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedInfo, SubjectPublicKeyInfo} from "../asn1/shemas/AttestationFramework";
import {Name} from "../asn1/shemas/InformationFramework";
import {AlgorithmIdentifierASN, Extensions} from "../asn1/shemas/AuthenticationFramework";
import {KeyPair} from "./KeyPair";

export class Attestation {
    protected version = 18; // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
    private serialNumber: any;
    // private signingAlgorithm:AlgorithmIdentifierASN;
    // der encoded
    protected signingAlgorithm:string;
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
    protected commitment: Uint8Array;
    // der encoded
    // protected extensions: string;
    protected extensions: Extensions;
    private signedInfo: Uint8Array;

    constructor(){}

    fromDerEncode( signedInfo: Uint8Array) {
        let decodedAttestationObj: SignedInfo = AsnParser.parse(uint8toBuffer(signedInfo), SignedInfo);

        this.signedInfo = signedInfo;
        this.version = decodedAttestationObj.version.version;
        this.serialNumber = decodedAttestationObj.serialNumber;

        this.signingAlgorithm = decodedAttestationObj.signature.algorithm.toString();

        if (decodedAttestationObj.validity){
            this.notValidBefore = decodedAttestationObj.validity.notBefore.generalizedTime.getTime();
            this.notValidAfter = decodedAttestationObj.validity.notAfter.generalizedTime.getTime();
        }
        // TODO enable it
        let rdn = decodedAttestationObj.subject.rdnSequence;
        if (rdn && rdn[0] && rdn[0][0]){
            let obj = rdn[0][0];
            this.subject = (obj.type.toString() == "2.5.4.3" ? "CN=" : "") + obj.value;
        }
        // this.subject = decodedAttestationObj.subject.rdnSequence;
        // TODO enable it
        this.subjectPublicKeyInfo = decodedAttestationObj.subjectPublicKeyInfo;
        this.subjectPublicKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(this.subjectPublicKeyInfo.value.subjectPublicKey)));

        this.issuer = decodedAttestationObj.issuer;
        // this = attestation.issuer;

        if (decodedAttestationObj.contract){
            this.smartcontracts = decodedAttestationObj.contract;
        }

        if (decodedAttestationObj.attestsTo.extensions){
            this.extensions = decodedAttestationObj.attestsTo.extensions;
            this.commitment = new Uint8Array(this.extensions.extension.extnValue);
        } else if(decodedAttestationObj.attestsTo.dataObject) {
            // TODO parse dataObject
            //this.extensions = decodedAttestationObj.attestsTo.dataObject;
        }
    }

    public isValidX509(): boolean {
        // if (this.version.getValue().intValueExact() != 0 && version.getValue().intValueExact() != 1  && version.getValue().intValueExact() != 2) {
        if (this.version != 18) {
            return false;
        }
        if (this.issuer == null || this.issuer.rdnSequence.length == 0) {
            return false;
        }
        if (this.notValidBefore == null || this.notValidAfter == null) {
            return false;
        }
        if (this.subject == null) {
            return false;
        }
        if (this.subjectPublicKeyInfo == null) {
            return false;
        }
        if (this.smartcontracts != null) {
            return false;
        }
        if (this.dataObject != null) {
            return false;
        }
        if (this.version == null || this.serialNumber == null || this.signingAlgorithm == null) {
            return false;
        }
        return true;
    }

    getDerEncoding(): string{
        return uint8tohex(new Uint8Array(this.signedInfo));
    }

    getCommitment(): Uint8Array{
        return this.commitment;
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
            || this.signingAlgorithm == null
            || (this.extensions == null && this.dataObject == null && !this.commitment)
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
        return this.signingAlgorithm;
    }


}
