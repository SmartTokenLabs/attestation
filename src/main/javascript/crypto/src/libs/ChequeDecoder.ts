import {base64ToUint8array} from "./utils";
import {MyAttestation} from "../asn1/shemas/AttestationFramework";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedCheque} from "../asn1/shemas/SignedCheque";

export class ChequeDecoder {
    constructor(base64str: string) {
        let uint8data = base64ToUint8array(base64str);
        const signedCheque: SignedCheque = AsnParser.parse(uint8data, SignedCheque);

        let amount: number = signedCheque.cheque.amount;
        // let validity = ASN1Sequence.getInstance(cheque.getObjectAt(1));
        // ASN1GeneralizedTime notValidBeforeEnc = ASN1GeneralizedTime.getInstance(validity.getObjectAt(0));
        // ASN1GeneralizedTime notValidAfterEnc = ASN1GeneralizedTime.getInstance(validity.getObjectAt(1));
        // long notValidBefore, notValidAfter;
        // try {
        //     notValidBefore = notValidBeforeEnc.getDate().getTime();
        //     notValidAfter = notValidAfterEnc.getDate().getTime();
        // } catch (ParseException e) {
        //     throw new IOException("Validity is not encoded properly");
        // }
        //
        // byte[] commitment = (ASN1OctetString.getInstance(cheque.getObjectAt(2))).getOctets();
        //
        // AsymmetricKeyParameter publicKey = SignatureUtility.restoreKey(DERBitString.getInstance(asn1.getObjectAt(1)).getEncoded());
        //
        // // Verify signature
        // byte[] signature = DERBitString.getInstance(asn1.getObjectAt(2)).getBytes();
        // return new Cheque(commitment, amount, notValidBefore, notValidAfter, signature, publicKey);
    }
}
