import {AttestationCrypto} from "./AttestationCrypto";
import {ProofOfExponent} from "./ProofOfExponent";
import {SignedAttestation} from "./SignedAttestation";
import {hexStringToArray, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {AttestableObject} from "./AttestableObject";

declare global {
    interface Window { ethereum: any; }
}

export class AttestedObject {
    private crypto: AttestationCrypto;
    private pok: ProofOfExponent;
    private unsignedEncoding: string;
    private derEncodedProof: string;
    private signature: string;
    constructor(
        private attestableObject: AttestableObject,
        private att: SignedAttestation,
        // private keys: KeyPair,
        private attestationSecret: bigint ,
        private chequeSecret: bigint
    ) {
        this.crypto = new AttestationCrypto();
        // this.userPublicKey = userKeys.getPublic();
        this.pok = this.makeProof(attestationSecret, chequeSecret, this.crypto);
        this.derEncodedProof = this.pok.getDerEncoding();

        let vec =
            this.attestableObject.getDerEncoding() +
            uint8tohex(this.att.getDerEncoding())+
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
    private makeProof(attestationSecret: bigint, objectSecret: bigint, crypto: AttestationCrypto): ProofOfExponent {
        // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
        // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
        let extensions = this.att.getUnsignedAttestation().getExtensions();//.getObjectAt(0));
        // Index in the second DER sequence is 2 since the third object in an extension is the actual value
        // let attCom = ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
        let attCom: Uint8Array = new Uint8Array(extensions.extension.extnValue);
        let objCom: Uint8Array = this.attestableObject.getCommitment();
        let pok: ProofOfExponent = crypto.computeEqualityProof(uint8tohex(attCom), uint8tohex(objCom), attestationSecret, objectSecret);
        if (!crypto.verifyEqualityProof(attCom, objCom, pok)) {
            throw new Error("The redeem proof did not verify");
        }
        return pok;
    }
/*
    checkValidity(){
        // CHECK: that it is an identity attestation otherwise not all the checks of validity needed gets carried out
        try {
            // let attEncoded: Uint8Array = this.att.getUnsignedAttestation().getDerEncoding();
            // TODO validate attestation
            // let std: IdentifierAttestation = new IdentifierAttestation(this.attEncoded);
            // CHECK: perform the needed checks of an identity attestation
            // if (!std.checkValidity()) {
            //     System.err.println("The attestation is not a valid standard attestation");
            //     return false;
            // }
        } catch (e) {
            console.log("The attestation is invalid");
            return false;
        }

        // CHECK: that the cheque is still valid
        if (!this.getAttestableObject().checkValidity()) {
            console.error("Cheque is not valid");
            return false;
        }

        // CHECK: verify signature on RedeemCheque is from the same party that holds the attestation
        // let spki = this.getAtt().getUnsignedAttestation().getSubjectPublicKeyInfo();

        // try {
        //     let parsedSubjectKey = spki.value.subjectPublicKey;
        //     if (!SignatureUtility.verify(this.unsignedEncoding, this.getSignature(), uint8tohex(new Uint8Array(parsedSubjectKey)))) {
        //         console.error("The signature on RedeemCheque is not valid");
        //         return false;
        //     }
        // } catch (e) {
        //     console.error("The attestation SubjectPublicKey cannot be parsed");
        //     return false;
        // }

        // CHECK: the Ethereum address on the attestation matches receivers signing key
        // TODO
        return true;
    }

 */

    getAttestableObject(){
        return this.attestableObject;
    }

    getAtt(){
        return this.att;
    }

    getDerEncodeProof(){
        return this.derEncodedProof;
    }
}
