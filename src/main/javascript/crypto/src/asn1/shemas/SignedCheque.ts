import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";

const AsnCRITICAL: boolean = false;

export class Cheque {
    @AsnProp({ type: AsnPropTypes.Integer }) public amount: string = "";
    @AsnProp({ type: AsnPropTypes.BitString }) public validity = AsnCRITICAL;
    @AsnProp({ type: AsnPropTypes.OctetString }) public commitment = AsnCRITICAL;
}

export class SignedCheque {

    @AsnProp({ type: Cheque })
    public cheque: string = "";

    @AsnProp({ type: AsnPropTypes.BitString })
    public publicKey = AsnCRITICAL;

    @AsnProp({ type: AsnPropTypes.BitString })
    public signatureValue = AsnCRITICAL;

}
