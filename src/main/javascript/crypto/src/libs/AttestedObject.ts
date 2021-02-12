import {AttestationCrypto} from "./AttestationCrypto";
import {SignedAttestation} from "./SignedAttestation";
import {uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {AttestableObject} from "./AttestableObject";
import {ProofOfExponentInterface} from "./ProofOfExponentInterface";

declare global {
    interface Window { ethereum: any; }
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
    constructor(
        private attestableObject: AttestableObject,
        private att: SignedAttestation,
        private attestationSecret: bigint ,
        private objectSecret: bigint
    ) {
        this.crypto = new AttestationCrypto();
        this.pok = this.makeProof(attestationSecret, objectSecret, this.crypto);
        this.derEncodedProof = this.pok.getDerEncoding();

        let vec =
            this.attestableObject.getDerEncoding() +
            this.att.getDerEncoding() +
            this.pok.getDerEncoding();
        this.unsignedEncoding = Asn1Der.encode('SEQUENCE_30', vec);
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
        let attCom: Uint8Array = this.att.getUnsignedAttestation().getRiddle();
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
}
