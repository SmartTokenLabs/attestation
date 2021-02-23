import {AttestationCrypto} from "./AttestationCrypto";
import {SignedAttestation} from "./SignedAttestation";
import {hexStringToArray, uint8ToBn, uint8toBuffer, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {AttestableObject} from "./AttestableObject";
import {ProofOfExponentInterface} from "./ProofOfExponentInterface";
import {KeyPair} from "./KeyPair";
import {Identity} from "../asn1/shemas/AttestationRequest";
import {AsnParser} from "@peculiar/asn1-schema";
import {UseToken} from "../asn1/shemas/UseToken";
import {UsageProofOfExponent} from "./UsageProofOfExponent";
import {Point} from "./Point";
import {IdentifierAttestation} from "./IdentifierAttestation";
import {Attestation} from "./Attestation";
import {Attestable} from "./Attestable";
import {SignatureUtility} from "./SignatureUtility";

declare global {
    interface Window {
        ethereum: any;
        web3: any;
    }
}

// TODO public AttestedObject(T object, SignedAttestation att, ProofOfExponent pok, byte[] signature,
//       AsymmetricKeyParameter userPublicKey) {
export class AttestedObject {
    private crypto: AttestationCrypto;
    private pok: ProofOfExponentInterface;
    private unsignedEncoding: string;
    private derEncodedProof: string;
    private signature: string;
    private encoding: string;
    private attestableObject: any;
    private att: SignedAttestation;
    private attestationSecret: bigint ;
    private objectSecret: bigint;
    private userPublicKey: Uint8Array;
    private userKeyPair: KeyPair;

    private preSignEncoded: string;

    constructor() {}

    create<T extends Attestable>(
        attestableObject: T ,
        att: SignedAttestation,
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

    fillPresignData(){
        this.preSignEncoded = this.attestableObject.getDerEncoding() +
            this.att.getDerEncoding() +
            this.pok.getDerEncoding();
        this.unsignedEncoding = Asn1Der.encode('SEQUENCE_30', this.preSignEncoded);
    }

    fromDecodedData<T extends Attestable>(
        attestableObject: T ,
        att: SignedAttestation,
        pok: ProofOfExponentInterface ,
        signature: string
    ){
        this.attestableObject = attestableObject;
        this.att = att;
        this.pok = pok;
        this.signature = signature;

        this.fillPresignData();

        let vec = this.preSignEncoded + Asn1Der.encode('BIT_STRING', this.signature)

        this.encoding = Asn1Der.encode('SEQUENCE_30', vec);
        this.userKeyPair = KeyPair.publicFromSubjectPublicKeyInfo(this.att.getUnsignedAttestation().getSubjectPublicKeyInfo());

        if (!this.verify()) {
            throw new Error("The redeem request is not valid");
        }
    }


    async sign(){
        this.signature = await SignatureUtility.signMessageWithBrowserWallet(this.unsignedEncoding);
        let vec = this.preSignEncoded +
            Asn1Der.encode('BIT_STRING', this.signature);
        this.encoding = Asn1Der.encode('SEQUENCE_30', vec);
        if (!this.verify()) {
            throw new Error("The redeem request is not valid");
        }
    }

    public checkValidity(): boolean {
        // CHECK: that it is an identity attestation otherwise not all the checks of validity needed gets carried out
        try {
            let attEncoded = this.att.getUnsignedAttestation().getDerEncoding();
            let std: IdentifierAttestation = new IdentifierAttestation()
            std.fromDerEncode(new Uint8Array(hexStringToArray(attEncoded)));

            // CHECK: perform the needed checks of an identity attestation
            if (!std.checkValidity()) {
                console.error("The attestation is not a valid standard attestation");
                return false;
            }
        } catch (e) {
            console.error("The attestation is invalid");
            return false;
        }

        // CHECK: that the cheque is still valid
        if (!this.getAttestableObject().checkValidity()) {
            console.error("Cheque is not valid");
            return false;
        }

        // CHECK: the Ethereum address on the attestation matches receivers signing key
        let attestationEthereumAddress: string = this.getAtt().getUnsignedAttestation().getSubject().substring(3);
        // TODO
        // if (!attestationEthereumAddress == this.getUserPublicKey()) {
        //     console.error("The attestation is not to the same Ethereum user who is sending this request");
        //     return false;
        // }

        // CHECK: verify signature on RedeemCheque is from the same party that holds the attestation
        if (this.signature != null) {
            let spki = this.getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();
            try {
                if (!KeyPair.publicFromSubjectPublicKeyInfo(spki).verifyHexStringWithEthereum(this.unsignedEncoding, this.signature)) {
                    console.error("The signature on RedeemCheque is not valid");
                    return false;
                }
            } catch (e) {
                console.error("The attestation SubjectPublicKey cannot be parsed");
                return false;
            }
        }

        return true;
    }


    verify(): boolean{
        //TODO
        let result: boolean =
            this.attestableObject.verify()
            && this.att.verify()
            && this.crypto.verifyEqualityProofUint8(
                this.att.getCommitment(),
                this.attestableObject.getCommitment(),
                this.pok
            );
        if (this.signature != null) {
            let spki = this.getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();
            return result && KeyPair.publicFromSubjectPublicKeyInfo(spki).verifyHexStringWithEthereum(this.unsignedEncoding, this.signature);
        } else {
            return result;
        }
    }

    static fromBytes<D extends UseToken>(asn1: Uint8Array, decoder: new () => D, attestorKey: KeyPair): AttestedObject{

        let attested: D = AsnParser.parse( uint8toBuffer(asn1), decoder);
        console.log(attested);
        // TODO decode Attested
        let me = new this();
        // TODO inject attestor key
        // let attestorPublicKey: KeyPair = new KeyPair();
        // me.att = SignedAttestation(attested.attestation, attestorPublicKey);
        // me.attestableObject = attested.signedDevconTicket;
        me.pok = UsageProofOfExponent.fromData(
            Point.decodeFromHex(uint8tohex(attested.proof.challengePoint)),
            uint8ToBn(attested.proof.responseValue) ) ;
        me.signature = uint8tohex(new Uint8Array(attested.signatureValue));

        return me;
    }


/*
    public async signFinalObject(){
        let vec =
            uint8tohex(this.attestableObject.getDerEncoding()) +
            uint8tohex(this.att.getDerEncoding())+
            this.pok.getDerEncoding();
        this.unsignedEncoding = Asn1Der.encode('SEQUENCE_30', vec);
        const hash = await ethers.utils.keccak256(hexStringToArray(this.unsignedEncoding));

        console.log('hash');
        console.log(hash);

        // TODO sign by user wallet
        // this.signature = SignatureUtility.sign(this.unsignedEncoding, userKeys.getPrivate());
        if (!window.ethereum){
            throw new Error('Please install metamask before.');
        }

        const provider = new ethers.providers.Web3Provider(window.ethereum);
        const signer = provider.getSigner();
        if (!signer) throw new Error("Active Wallet required");

        const userAddress = await signer.getAddress();

        console.log('lets sign message');
        const metamaskEnabled = await window.ethereum.enable();

        if (!metamaskEnabled){
            throw new Error("Active Wallet required");
        }

        // console.log(this.unsignedEncoding);

        // let signature = await signer.signMessage(hexStringToArray(this.unsignedEncoding));
        let signature = await signer.signMessage(ethers.utils.arrayify(hash));
        console.log('signature');
        console.log(signature);

        if (!signature){
            throw new Error("Cant sign data");
        }

        const ethereumHash = await ethers.utils.keccak256("\x19Ethereum Signed Message:\n" + hash.length + hash);
        const pk = ethers.utils.recoverPublicKey(ethereumHash, signature);
        const recoveredAddress = ethers.utils.computeAddress(ethers.utils.arrayify(pk));

        console.log('recoveredAddress');
        console.log(recoveredAddress);

        //     vec.add(new DERBitString(this.signature));
        //     this.encoding = new DERSequence(vec).getEncoded();
        // } catch (IOException e) {
        //     throw new RuntimeException(e);
        // }
        // if (!verify()) {
        //     throw new IllegalArgumentException("The redeem request is not valid");
        // }
    }
*/
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

        if (!crypto.verifyEqualityProof(uint8tohex(attCom), uint8tohex(objCom), pok)) {
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

    public getDerEncodingWithSignature() { return this.encoding; }

    // TODO type it
    public getDerEncoding() {
        return this.unsignedEncoding;
    }

    public getUserPublicKey() {
        return this.userPublicKey;
    }
}
