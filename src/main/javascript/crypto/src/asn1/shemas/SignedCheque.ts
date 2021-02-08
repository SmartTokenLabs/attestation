import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {ValidityValue} from "./AuthenticationFramework";

const AsnCRITICAL: boolean = false;

export class ChequeASN {
    @AsnProp({ type: AsnPropTypes.Integer }) public amount: AsnPropTypes.Integer;
    @AsnProp({ type: ValidityValue }) public validity:ValidityValue;
    @AsnProp({ type: AsnPropTypes.OctetString }) public commitment: AsnPropTypes.OctetString;
}

export class SignedCheque {

    @AsnProp({ type: ChequeASN })
    public cheque: ChequeASN;

    @AsnProp({ type: AsnPropTypes.BitString })
    public publicKey: Uint8Array;

    @AsnProp({ type: AsnPropTypes.BitString })
    public signatureValue: Uint8Array;

}
