import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {ProofOfExponent} from "./ProofOfExponent";

export class AttestedObject {
    private crypto: AttestationCrypto;
    private pok: ProofOfExponent;
    constructor(private attestableObject: string, private att: string, private keys: KeyPair, private attestationSecret: bigint ,private chequeSecret: bigint) {
        this.crypto = new AttestationCrypto();
        // this.userPublicKey = userKeys.getPublic();

        // this.pok = this.makeProof();
    //     ASN1EncodableVector vec = new ASN1EncodableVector();
    //     vec.add(ASN1Sequence.getInstance(this.attestableObject.getDerEncoding()));
    //     vec.add(ASN1Sequence.getInstance(att.getDerEncoding()));
    //     vec.add(ASN1Sequence.getInstance(pok.getDerEncoding()));
    //     this.unsignedEncoding = new DERSequence(vec).getEncoded();
    //     this.signature = SignatureUtility.signDeterministic(this.unsignedEncoding, userKeys.getPrivate());
    //     vec.add(new DERBitString(this.signature));
    //     this.encoding = new DERSequence(vec).getEncoded();
    // } catch (IOException e) {
    //     throw new RuntimeException(e);
    // }
    // if (!verify()) {
    //     throw new IllegalArgumentException("The redeem request is not valid");
    // }
    }

    // private makeProof(): ProofOfExponent {
    //     // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
    //     // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    //     // let extensions = DERSequence.getInstance(att.getUnsignedAttestation().getExtensions().getObjectAt(0));
    //     // // Index in the second DER sequence is 2 since the third object in an extension is the actual value
    //     // byte[] attCom = ASN1OctetString.getInstance(extensions.getObjectAt(2)).getOctets();
    //     // ProofOfExponent pok = crypto.computeEqualityProof(attCom, attestableObject.getCommitment(), attestationSecret, objectSecret);
    //     // if (!crypto.verifyEqualityProof(attCom, attestableObject.getCommitment(), pok)) {
    //     // throw new RuntimeException("The redeem proof did not verify");
    // // }
    // return pok;
    // }
}
