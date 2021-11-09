import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {Attestation} from "./Attestation";
import {Validateable} from "./Validateable";
import {logger} from "./utils";
import {DEBUGLEVEL} from "../config";
import {Asn1Der, x500NameData} from "./DerUtility";

export class IdentifierAttestation extends Attestation implements Validateable{
    private crypto: AttestationCrypto;
    static OID_OCTETSTRING = "1.3.6.1.4.1.1466.115.121.1.40";
    // ECDSA with recommended (for use with keccak signing since there is no explicit standard OID for this)
    public static DEFAULT_SIGNING_ALGORITHM = "1.2.840.10045.4.2";
    public static HIDDEN_IDENTIFIER_VERSION = 18;
    public static NFT_VERSION = 19;
    public static HIDDEN_TYPE = "HiddenType";
    public static HIDDEN_IDENTIFIER = "HiddenIdentifier";

    // SEE RFC 2079
    public static LABELED_URI = "1.3.6.1.4.1.250.1.57";
    public static LABELED_URI_LABEL = "labeledURI";

    private type:string;
    private identifier:string;

    constructor() {
        super();
    }

    fromCommitment(commitment: Uint8Array, keys: KeyPair){

        this.subjectKey = keys;
        this.setVersion(IdentifierAttestation.HIDDEN_IDENTIFIER_VERSION);
        this.setSubject("CN=");
        this.setSigningAlgorithm(IdentifierAttestation.DEFAULT_SIGNING_ALGORITHM);

        this.setSubjectPublicKeyInfo(keys);
        this.setCommitment(commitment);

        this.type = IdentifierAttestation.HIDDEN_TYPE;
        this.identifier = IdentifierAttestation.HIDDEN_IDENTIFIER;

        this.setUnlimitedValidity();
    }

    private setUnlimitedValidity(){
        super.setNotValidBefore(Date.now());
        // This is used to indicate unlimited validity, see https://tools.ietf.org/html/rfc5280#section-4.1.2.5
        super.setNotValidAfter(Date.parse('31 Dec 9999 23:59:59'));
    }

    static fromData(identifier: string, type: number, keys: KeyPair, secret: bigint){
        let crypto = new AttestationCrypto();
        let commitment = crypto.makeCommitment(identifier, type, secret);
        let me = new this();
        me.fromCommitment(commitment, keys);
        me.type = type.toString();
        me.identifier = identifier;
        return me;
    }

    static fromLabelAndUrl(label: string, URL: string, keys: KeyPair){

        let me = new this();

        me.subjectKey = keys;
        me.setVersion(IdentifierAttestation.NFT_VERSION);
        me.setSubject(me.makeLabeledURI(label, URL));
        me.setSigningAlgorithm(IdentifierAttestation.DEFAULT_SIGNING_ALGORITHM);
        me.setIssuer("CN=attestation.id");
        me.setSerialNumber(1);

        me.setSubjectPublicKeyInfo(keys);
        me.setUnlimitedValidity();

        me.type = label;
        me.identifier = URL;
        return me;
    }

    /**
     * @param label the label of the URL, similar to what is inside <a>...</a>
     * @param URL the URL itself, similar to what is in <a href="...">, note that
     * it should already be URLencoded therefore not containing space
     */
    private makeLabeledURI(label: string, URL: string): string {

        // DERUTF8String labeledURLValue = new DERUTF8String(URL + " " + label);
        // RDN rdn = new RDN(LABELED_URI, labeledURLValue);
        // return new X500Name(new RDN[] {rdn});
        // https://docs.microsoft.com/ru-ru/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding
        // let type = Asn1Der.encode("OBJECT_ID", IdentifierAttestation.LABELED_URI);
        // let value = Asn1Der.encode("UTF8STRING", URL + " " + label);
        //
        // let rdn = Asn1Der.encode("SEQUENCE_30", type + value);
        // let set = Asn1Der.encode("SET", rdn);
        //
        // return Asn1Der.encode("SEQUENCE_30", set);
        return `${IdentifierAttestation.LABELED_URI_LABEL}="${URL} ${label}"`;
    }

    static fromBytes(bytes: Uint8Array){
        let me = new this();
        me.fromBytes(bytes);
        if (!me.checkValidity()) {
            throw new Error("Could not validate object");
        }
        if (me.getVersion() == IdentifierAttestation.NFT_VERSION) {
            let x500Arr = Asn1Der.parseX500Names(me.getSubject());
            let found = false;
            x500Arr.forEach((item:x500NameData)=>{
                if (found) return;
                if (item.type == IdentifierAttestation.LABELED_URI_LABEL) {
                    found = true;
                    let typeAndIdentifier = item.value.split(' ');
                    if (typeAndIdentifier.length != 2) {
                        throw new Error("LabeledURI values should be separated with space and 2 items only: " + item.value);
                    }
                    me.type = typeAndIdentifier[0];
                    me.identifier = typeAndIdentifier[1];
                }
            })
            if (!found) { throw new Error("Cant find LABELED_URI"); }
        } else {
            me.type = IdentifierAttestation.HIDDEN_TYPE;
            me.identifier = IdentifierAttestation.HIDDEN_IDENTIFIER;
        }

        return me;
    }

    setSubjectPublicKeyInfo(keys: KeyPair){
        this.subjectKey = keys;
    }

    setCommitment(encodedRiddle: Uint8Array) {
        this.commitment = encodedRiddle;
    }

    checkValidity(): boolean {
        if (!super.checkValidity()) {
            logger(DEBUGLEVEL.LOW, "IdentifierAttestation super.checkValidity() filed;")
            return false;
        }
        if (this.getVersion() != IdentifierAttestation.HIDDEN_IDENTIFIER_VERSION && this.getVersion() != IdentifierAttestation.NFT_VERSION) {
            logger(DEBUGLEVEL.LOW, "The version number is " + this.getVersion() + ", it must be either " + IdentifierAttestation.HIDDEN_IDENTIFIER_VERSION + " or " + IdentifierAttestation.NFT_VERSION);
            return false;
        }
        if (this.getSigningAlgorithm() !== IdentifierAttestation.DEFAULT_SIGNING_ALGORITHM) {
            logger(DEBUGLEVEL.LOW, "The subject is supposed to only be an Ethereum address as the Common Name");
            return false;
        }

        if (this.getVersion() == IdentifierAttestation.NFT_VERSION) {
            if (!this.subject.includes(IdentifierAttestation.LABELED_URI_LABEL+"=")) {
                logger(DEBUGLEVEL.LOW, "A NFT Identifier attestation must have a labeled uri as subject. subject = " + this.getSubject());
                return false;
            }
        }

        if (this.getVersion() == IdentifierAttestation.HIDDEN_IDENTIFIER_VERSION) {
            // Ensure that there is a commitment as part of the attestation
            if (this.getCommitment().length < AttestationCrypto.BYTES_IN_DIGEST) {
                logger(DEBUGLEVEL.LOW, "The attestation does not contain a valid commitment");
                return false;
            }
        }

        return true;
    }

    setIssuer(issuer: string){
        this.issuer = issuer;
    }

    public getSerialNumber(): number {
        return this.serialNumber;
    }

    public setSerialNumber(serialNumber: number) {
        this.serialNumber = serialNumber;
    }

    public getAddress(): string {
        // Remove the "CN=" prefix
        return this.subjectKey.getAddress();
    }
}
