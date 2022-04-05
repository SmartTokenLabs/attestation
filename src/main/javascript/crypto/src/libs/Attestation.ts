import {hexStringToUint8, uint8toBuffer, uint8tohex, logger} from "./utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedInfo} from "../asn1/shemas/AttestationFramework";
import {Extensions} from "../asn1/shemas/AuthenticationFramework";
import {KeyPair} from "./KeyPair";
import {Asn1Der, X500NamesLabels} from "./DerUtility";
import {Timestamp} from "./Timestamp";
import {DEBUGLEVEL} from "../config";
import {AttributeTypeAndValue} from "../asn1/shemas/InformationFramework";

export class Attestation {
    static OID_OCTETSTRING: string = "1.3.6.1.4.1.1466.115.121.1.40";
    protected version = 18; // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
    protected serialNumber: any;
    // private signingAlgorithm:AlgorithmIdentifierASN;
    // der encoded
    protected signingAlgorithm:string;
    protected issuer: string; // X500Name value Optional
    private notValidBefore: any;// Optional
    private notValidAfter: any;// Optional
    private blockchainFriendly: boolean = true;
    //private subject: Name;  //X500Name  CN=Ethereum address     // Optional
    // der encoded
    protected subject: string;  //X500Name  CN=Ethereum address     // Optional
    // protected subjectPublicKeyInfo: SubjectPublicKeyInfo;    // Optional
    // der encoded
    //protected subjectPublicKeyInfo: string;    // Optional
    protected subjectKey: KeyPair;    // Optional
    private smartcontracts: any; // ASN1integers  // Optional
    private dataObject: any;
    protected commitment: Uint8Array;
    // der encoded
    // protected extensions: string;
    protected extensions: Extensions;
    private signedInfo: Uint8Array;

    constructor(){}

    private parseNames(rdn:AttributeTypeAndValue[]):string{
        let invertedX500NamesLabels:{[index: string]:string} = {};
        Object.keys(X500NamesLabels).forEach((key:string)=>{
            invertedX500NamesLabels[X500NamesLabels[key].toLowerCase()] = key;
        })
        let nameArray: string[] = [];
        rdn.forEach((obj:AttributeTypeAndValue)=>{
            let type = invertedX500NamesLabels[obj.type.toString().toLowerCase()];
            if (!type) throw new Error(`X500 with name ${obj.type.toString()} not implemented yet.`)
            nameArray.push(`${type}="${obj.value}"`);
        })
        return nameArray.join(',');
    }

    fromBytes( uint8bytes: Uint8Array) {

        const me = this;
        let decodedAttestationObj: SignedInfo = AsnParser.parse(uint8toBuffer(uint8bytes), SignedInfo);

        me.signedInfo = uint8bytes;
        me.version = decodedAttestationObj.version.version;
        me.serialNumber = decodedAttestationObj.serialNumber;

        me.signingAlgorithm = decodedAttestationObj.signature.algorithm.toString();

        if (decodedAttestationObj.validity){
            me.notValidBefore = decodedAttestationObj.validity.notBefore.generalizedTime.getTime();
            me.notValidAfter = decodedAttestationObj.validity.notAfter.generalizedTime.getTime();
            // TODO validate time when it will be updated in Java code
            // if (
            //     (decodedAttestationObj.validity.notAfterInt && (decodedAttestationObj.validity.notAfterInt * 1000 != me.notValidAfter )) ||
            //     (decodedAttestationObj.validity.notBeforeInt && (decodedAttestationObj.validity.notBeforeInt * 1000!= me.notValidBefore ))
            //     ) {
            //     throw new Error("Date doesnt fit");
            // }
            if (typeof decodedAttestationObj.validity.notBeforeInt === 'undefined' || typeof decodedAttestationObj.validity.notAfterInt === 'undefined') {
                this.blockchainFriendly = false;
            } else {
                this.blockchainFriendly = true;
            }
        }

        let rdn = decodedAttestationObj.subject.rdnSequence;
        me.subject = "";

        if (rdn && rdn[0] && rdn[0].length){
            me.subject = this.parseNames(rdn[0]);
        }

        me.subjectKey = KeyPair.publicFromSubjectPublicKeyInfo(decodedAttestationObj.subjectPublicKeyInfo);

        let issuerSet = decodedAttestationObj.issuer.rdnSequence;
        me.issuer = '';
        if (issuerSet.length) {
            me.issuer = this.parseNames(issuerSet[0]);
        }

        if (decodedAttestationObj.contract){
            me.smartcontracts = decodedAttestationObj.contract;
        }

        if (decodedAttestationObj.attestsTo && decodedAttestationObj.attestsTo.extensions){
            me.extensions = decodedAttestationObj.attestsTo.extensions;
            me.commitment = new Uint8Array(me.extensions.extension.extnValue);
        } else if(decodedAttestationObj.attestsTo && decodedAttestationObj.attestsTo.dataObject) {
            throw new Error("Implement parse dataObject");
            // TODO parse dataObject
            //this.extensions = decodedAttestationObj.attestsTo.dataObject;
        }
    }

    public isValidX509(): boolean {
        if (this.version != 0
            && this.version != 1
            && this.version != 2) {
            logger(DEBUGLEVEL.LOW,"Incorrect version number");
            return false;
        }
        if (!this.issuer) {
            logger(DEBUGLEVEL.LOW,"Issuer info not set");
            return false;
        }
        if (this.notValidBefore == null || this.notValidAfter == null) {
            logger(DEBUGLEVEL.LOW,"Validity period not set");
            return false;
        }
        if (this.subject == null) {
            logger(DEBUGLEVEL.LOW,"Subject info not set");
            return false;
        }
        if (!this.subjectKey) {
            logger(DEBUGLEVEL.LOW, "No subject public key info set");
            return false;
        }
        if (this.smartcontracts != null) {
            logger(DEBUGLEVEL.LOW, "Smart contract info set");
            return false;
        }
        if (this.dataObject != null) {
            logger(DEBUGLEVEL.LOW, "Data object set");
            return false;
        }
        if (this.version == null || this.serialNumber == null || this.signingAlgorithm == null) {
            logger(DEBUGLEVEL.LOW, "Version, serial number, subject or algorithm missing");
            return false;
        }
        return true;
    }

    getDerEncoding(): string{
        if (!this.signedInfo) {
            this.signedInfo = this.getPrehash();
        }
        if (!this.signedInfo) {
            throw new Error('Empty Attestaion Der Encoding');
        }
        return uint8tohex(new Uint8Array(this.signedInfo));
    }

    getCommitment(): Uint8Array{
        return this.commitment;
    }

    getNotValidBefore(): number{
        return this.notValidBefore;
    }

    setNotValidBefore(d: number){
        this.notValidBefore = d;
    }

    getNotValidAfter(): number{
        return this.notValidAfter;
    }

    setNotValidAfter(d: number){
        this.notValidAfter = d;
    }

    getSubjectPublicKeyInfo(){
        return this.subjectKey;
    }

    checkValidity(){
        if (this.version == null) {
            logger(DEBUGLEVEL.LOW, "Attest version missed");
            return false;
        }

        if (this.serialNumber == null) {
            logger(DEBUGLEVEL.LOW, "Attest serial number missed");
            return false;
        }

        if (this.subject == null) {
            logger(DEBUGLEVEL.LOW, "Attest subject missed");
            return false;
        }

        if (this.signingAlgorithm == null) {
            logger(DEBUGLEVEL.LOW, "Attest signing algorithm missed");
            return false;
        }

        let attNotBefore = this.getNotValidBefore();
        let attNotAfter = this.getNotValidAfter();

        let timestamp:Timestamp = new Timestamp(attNotBefore);
        timestamp.setValidity(attNotAfter - attNotBefore);
        if (!timestamp.validateAgainstExpiration(attNotAfter)) {
            return false;
        }

        if (this.extensions != null && this.dataObject != null) {
            logger(DEBUGLEVEL.LOW, "Both Extensions and dataObject not allowed");
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
        this.subject = subject;
    }

    getSubject(): string{
        return this.subject;
    }

    setSigningAlgorithm(alg: string) {
        this.signingAlgorithm = alg;
    }

    public getPrehash(): Uint8Array {
        if (!this.checkValidity()) {
            return null;
        }
        // = 0x10+0x02 where 0x02 means x509 v3 (v1 has version 0) and 0x10 is Attestation v 0
        // new DERTaggedObject(true, 0, this.version);
        let res: string = Asn1Der.encode('TAG', Asn1Der.encode('INTEGER', this.version),0)
        + Asn1Der.encode('INTEGER', this.serialNumber)
            // TODO verify encoding!!!
        + Asn1Der.encodeObjectId(this.signingAlgorithm);
        res += this.issuer ? Asn1Der.encodeName(this.issuer) : Asn1Der.encode('NULL_VALUE','');

        if (this.notValidAfter != null && this.notValidBefore != null) {
            let date = 
                Asn1Der.encode('GENERALIZED_TIME', this.notValidBefore)
                + (this.blockchainFriendly ? Asn1Der.encode('INTEGER', Math.floor(this.notValidBefore)): "")
                + Asn1Der.encode('GENERALIZED_TIME', this.notValidAfter)
                + (this.blockchainFriendly ? Asn1Der.encode('INTEGER', Math.floor(this.notValidAfter)) : "");
            res += Asn1Der.encode('SEQUENCE_30', date);
        } else {
            res += Asn1Der.encode('NULL_VALUE','');
        }

        // res.add(this.subject == null ? new DERSequence() : this.subject);

        // res += this.subject ? Asn1Der.encodeName(this.subject) : Asn1Der.encode('NULL_VALUE','');
        res += this.subject ? Asn1Der.encodeName(this.subject) : Asn1Der.encode('NULL_VALUE','');

        res += this.subjectKey ? this.subjectKey.getAsnDerPublic() : Asn1Der.encode('NULL_VALUE','');

        if (this.smartcontracts != null) {
            res += this.smartcontracts;
        }

        // if (this.commitment && this.commitment.length){
        //     let extensions: string = Asn1Der.encode('OBJECT_ID', Attestation.OID_OCTETSTRING)
        //         + Asn1Der.encode('BOOLEAN', 1)
        //         + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment));
        //     // Double Sequence is needed to be compatible with X509V3
        //     res += Asn1Der.encode('TAG',Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('SEQUENCE_30', extensions)),3);
        // }


        // The validity check ensure that only one of "extensions" and "dataObject" is set
        if (this.extensions != null) {
            res += Asn1Der.encode('TAG',Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('SEQUENCE_30', this.extensions)),3);
        }

        if (this.dataObject != null) {
            res += Asn1Der.encode('TAG',Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('SEQUENCE_30', this.dataObject)),4);
        }

        return hexStringToUint8(Asn1Der.encode('SEQUENCE_30',res));
    }

    public getSigningAlgorithm() {
        return this.signingAlgorithm;
    }
}
