import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";
import { ValidityValue, AlgorithmIdentifierASN} from "./AuthenticationFramework";

// @AsnType({ type: AsnTypeTypes.Choice })
// class StringOrInteger {
//     @AsnProp({ type: AsnPropTypes.Integer}) public tiketIdNumber?: BigInt;
//     @AsnProp({ type: AsnPropTypes.Utf8String }) public tiketIdString?: string;
// }

export class DevconTicket {
    @AsnProp({ type: AsnPropTypes.Utf8String }) public devconId: string;
    // @AsnProp({ type: StringOrInteger }) public ticketId: StringOrInteger;
    @AsnProp({ type: AsnPropTypes.Integer, optional: true}) public ticketIdNumber?: BigInt;
    @AsnProp({ type: AsnPropTypes.Utf8String, optional: true }) public ticketIdString?: string;
    @AsnProp({ type: AsnPropTypes.Integer }) public ticketClass: number;
    @AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public commitment?: Uint8Array;
}

export class SignedDevconTicket {

    @AsnProp({ type: DevconTicket })
    public ticket: DevconTicket;

    @AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public commitment?: Uint8Array;

    @AsnProp({ type: AsnPropTypes.BitString })
    public signatureValue: Uint8Array;

}
