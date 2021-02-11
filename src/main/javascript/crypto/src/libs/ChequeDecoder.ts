import {base64ToUint8array, uint8tohex} from "./utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedCheque} from "../asn1/shemas/SignedCheque";
import {KeyPair} from "./KeyPair";
import {Cheque} from "./Cheque";

export class ChequeDecoder {
    constructor() {
    }
    static fromBase64 (base64str: string) {
        let uint8data = base64ToUint8array(base64str);
        const signedCheque: SignedCheque = AsnParser.parse(uint8data, SignedCheque);

        let amount: number = signedCheque.cheque.amount;
        let notValidBefore: number = signedCheque.cheque.validity.notBefore.generalizedTime.getTime();
        let notValidAfter: number = signedCheque.cheque.validity.notAfter.generalizedTime.getTime();
        // console.log('signedCheque',signedCheque);

        let commitment = new Uint8Array(signedCheque.cheque.commitment);
        let publicKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(signedCheque.publicKey)))

        let signature = new Uint8Array(signedCheque.signatureValue);

        return Cheque.fromData(commitment, amount, notValidBefore, notValidAfter, signature, publicKey);
    }
}
