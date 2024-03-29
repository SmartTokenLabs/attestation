import {AttestationCrypto} from "./AttestationCrypto";
import {SignedIdentifierAttestation} from "./SignedIdentifierAttestation";
import {hexStringToArray, logger, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {ProofOfExponentInterface} from "./ProofOfExponentInterface";
import {KeyPair, KeysArray} from "./KeyPair";
import {AsnParser} from "@peculiar/asn1-schema";
import {UseToken} from "../asn1/shemas/UseToken";
import {UsageProofOfExponent} from "./UsageProofOfExponent";
import {IdentifierAttestation} from "./IdentifierAttestation";
import {Attestable} from "./Attestable";
import {Verifiable} from "./Verifiable";
import {ASNEncodable} from "./ASNEncodable";
import {AttestableObject} from "./AttestableObject";
import {DEBUGLEVEL} from "../config";

declare global {
    interface Window {
        ethereum: any;
        web3: any;
    }
}


export class AttestedObject implements ASNEncodable, Verifiable {
    private crypto: AttestationCrypto;
    private pok: ProofOfExponentInterface;
    private derEncodedProof: string;
    private encoding: string;
    private attestableObject: any;
    private att: SignedIdentifierAttestation;
    private attestationSecret: bigint;
    private objectSecret: bigint;
    private userKeyPair: KeyPair;

    private preSignEncoded: string;

    private webDomain: string;

    static Eip712UserData: {[index: string]:string|number}  = {
        payload: '',
        description: '',
        timestamp: 0
    }
    // static Eip712UserDataTypes: {[index: string]:string}[]  = [
    static Eip712UserDataTypes: {name: string, type: string}[]  = [
        {name: 'payload', type: 'string'},
        {name: 'description', type: 'string'},
        {name: 'timestamp', type: 'uint256'},
    ]
    static Eip712UserDataPrimaryName: string = "Authentication";
    static Eip712UserDataDescription: string = "Single-use authentication";

    constructor() {}

    create<T extends Attestable>(
        attestableObject: T ,
        att: SignedIdentifierAttestation,
        attestationSecret: bigint ,
        objectSecret: bigint
    ){
        this.attestableObject = attestableObject;
        this.att = att;
        this.attestationSecret = attestationSecret;
        this.objectSecret = objectSecret;
        this.crypto = new AttestationCrypto();
        this.pok = this.makeProof(attestationSecret, objectSecret, this.crypto);
        this.derEncodedProof = this.pok.getDerEncoding();

        this.fillPresignData();

    }

    setWebDomain(domain: string){
        this.webDomain = domain;
    }

    fillPresignData(){
        this.preSignEncoded = 
            this.attestableObject.getDerEncoding() +
            this.att.getDerEncoding() +
            this.pok.getDerEncoding();

        this.encoding = Asn1Der.encode('SEQUENCE_30', this.preSignEncoded);
    }

    fromDecodedData<T extends Attestable>(
        attestableObject: T ,
        att: SignedIdentifierAttestation,
        pok: ProofOfExponentInterface
    ){
        this.attestableObject = attestableObject;
        this.att = att;
        this.pok = pok;

        this.fillPresignData();

        this.userKeyPair = this.att.getUnsignedAttestation().getSubjectPublicKeyInfo();

        this.constructorCheck();
    }


    // async sign(){
    //     let userData = {
    //         payload: this.encoding,
    //         description: AttestedObject.Eip712UserDataDescription,
    //         timestamp: new Date().getTime()
    //     };
    //
    //     return await SignatureUtility.signEIP712WithBrowserWallet(this.webDomain, userData, AttestedObject.Eip712UserDataTypes, AttestedObject.Eip712UserDataPrimaryName );
    // }

    public verify(): boolean{
        if (!this.attestableObject.verify()) {
            logger(DEBUGLEVEL.LOW, "Could not verify attestable object");
            return false;
        }
        if (!this.att.verify()) {
            logger(DEBUGLEVEL.LOW, "Could not verify attestation");
            return false;
        }
        if (!this.crypto.verifyEqualityProof(
            this.att.getUnsignedAttestation().getCommitment(),
            this.attestableObject.getCommitment(),
            this.pok
        )) {
            logger(DEBUGLEVEL.LOW, "Could not verify the consistency between the commitment in the attestation and the attested object");
            return false;
        }

        return true;
    }

    static fromBytes<D extends UseToken, T extends AttestableObject>(asn1: Uint8Array, decoder: new () => D, attestorKey: KeyPair, attestable: new () => T, issuerKeys: KeysArray): AttestedObject{

        let attested: D = AsnParser.parse(asn1, decoder);

        let me = new this();

        me.attestableObject = new attestable();
        me.attestableObject.fromBytes(attested.signedToken, issuerKeys);

        me.att = SignedIdentifierAttestation.fromBytes(new Uint8Array(attested.attestation), attestorKey);

        let pok = new UsageProofOfExponent();
        pok.fromBytes( new Uint8Array(attested.proof) ) ;
        me.pok = pok;

        me.userKeyPair = me.att.getUnsignedAttestation().getSubjectPublicKeyInfo();

        // TODO: Use getter to instantiate AttestationCrypto when required
        me.crypto = new AttestationCrypto();

        me.constructorCheck();

        return me;
    }

    private makeProof(attestationSecret: bigint, objectSecret: bigint, crypto: AttestationCrypto): ProofOfExponentInterface {
        // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
        // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
        // TODO we dont parse that value, because its already parsed to this.riddle
        // let extensions = this.att.getUnsignedAttestation().getExtensions();//.getObjectAt(0));

        // Index in the second DER sequence is 2 since the third object in an extension is the actual value

        // TODO we dont parse that value, because its already parsed to this.riddle
        // let attCom: Uint8Array = new Uint8Array(extensions.extension.extnValue);
        let attCom: Uint8Array = this.att.getUnsignedAttestation().getCommitment();
        let objCom: Uint8Array = this.attestableObject.getCommitment();
        let pok: ProofOfExponentInterface = crypto.computeEqualityProof(uint8tohex(attCom), uint8tohex(objCom), attestationSecret, objectSecret);

        if (!crypto.verifyEqualityProof(attCom, objCom, pok)) {
            throw new Error("The redeem proof did not verify");
        }
        return pok;
    }

    getAttestableObject(){
        return this.attestableObject;
    }

    getAtt(){
        return this.att;
    }

    getDerEncodeProof(){
        return this.derEncodedProof;
    }

    public getDerEncoding():string {
        return this.encoding;
    }

    private constructorCheck() {
        if (!this.verify()) {
            throw new Error("The redeem request is not valid");
        }
    }

    public checkValidity(ethAddress:string = ""): boolean {

        // CHECK: that it is an identifier attestation otherwise not all the checks of validity needed gets carried out
        try {
            let attEncoded = this.att.getUnsignedAttestation().getDerEncoding();
            let std: IdentifierAttestation = IdentifierAttestation.fromBytes(new Uint8Array(hexStringToArray(attEncoded))) as IdentifierAttestation;

            // CHECK: perform the needed checks of an identifier attestation
            if (!std.checkValidity()) {
                logger(DEBUGLEVEL.LOW, "The attestation is not a valid standard attestation");
                return false;
            }
        } catch (e) {
            logger(DEBUGLEVEL.LOW, "The attestation is invalid");
            return false;
        }

        try {
            // CHECK: that the cheque is still valid
            if (!this.getAttestableObject().checkValidity()) {
                logger(DEBUGLEVEL.LOW, "Cheque is not valid");
                return false;
            }
        } catch (e) {
            logger(DEBUGLEVEL.LOW, "Cheque validation failed");
            return false;
        }

		if (!ethAddress)
			return true;

        try {

            // CHECK: the Ethereum address on the attestation matches receivers signing key
            // let attestationEthereumAddress: string = this.getAtt().getUnsignedAttestation().getSubject().substring(3);
            let attestationEthereumAddress: string = this.getAtt().getUnsignedAttestation().getAddress();
            logger(DEBUGLEVEL.HIGH, 'attestationEthereumAddress: ' + attestationEthereumAddress);
            logger(DEBUGLEVEL.HIGH, 'providedEthereumAddress: ' + ethAddress);

            if (attestationEthereumAddress.toLowerCase() !== ethAddress.toLowerCase()) {
                logger(DEBUGLEVEL.LOW, "The attestation is not to the same Ethereum user who is sending this request");
                return false;
            }
        } catch (e) {
            logger(DEBUGLEVEL.LOW, "Address validation failed");
            logger(DEBUGLEVEL.MEDIUM, e);
            return false;
        }

        return true;
    }
}
