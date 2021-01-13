import {AsnArray, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";
import {Null} from "asn1js";

/*
export class AttributeTypeAndValue {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier}) // AttributeType, AttributeType ::= OBJECT IDENTIFIER
    public type?: AsnPropTypes.ObjectIdentifier;
    @AsnProp({ type: AsnPropTypes.Any}) // AttributeValue, AttributeValue ::= ANY -- DEFINED BY AttributeType
    public value?: AsnPropTypes.Any;
}

// RelativeDistinguishedName ::=
//     SET SIZE (1..MAX) OF AttributeTypeAndValue
// @AsnType({ type: AsnTypeTypes.Set })
export class RelativeDistinguishedName {
    @AsnProp({ type: AttributeTypeAndValue})
    public rdnSequence?: AttributeTypeAndValue;
}

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// export class RDNSequence {
//     @AsnProp({ type: RelativeDistinguishedName})
//     public rdnSequence?: RelativeDistinguishedName;
// }
// TODO make correct SET description
// @AsnType({ type: AsnTypeTypes.Set })
export class RDNSequence {
    @AsnProp({ type: AsnPropTypes.Any})
    public rdnSequence: AsnPropTypes.Any;
}

@AsnType({ type: AsnTypeTypes.Choice })
export class Name {
    @AsnProp({ type: RDNSequence})
    public rdnSequence?: RDNSequence;
    @AsnProp({ type: AsnPropTypes.Any })
    public null?: Null;
}
*/

class AttributeTypeAndValue {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    type: string;

    @AsnProp({ type: AsnPropTypes.Any })
    value: ArrayBuffer;
}

@AsnType({ type: AsnTypeTypes.Set, itemType: AttributeTypeAndValue })
class RelativeDistinguishedName extends AsnArray<AttributeTypeAndValue> {
    constructor(items?: AttributeTypeAndValue[]) {
        super(items);
        Object.setPrototypeOf(this, RelativeDistinguishedName.prototype);
    }
}

@AsnType({ type: AsnTypeTypes.Sequence, itemType: RelativeDistinguishedName })
class RDNSequence extends AsnArray<RelativeDistinguishedName> {
    constructor(items?: RelativeDistinguishedName[]) {
        super(items);
        Object.setPrototypeOf(this, RDNSequence.prototype);
    }
}

@AsnType({ type: AsnTypeTypes.Choice })
export class Name {
    @AsnProp({ type: RDNSequence })
    rdnSequence?: RDNSequence;

    @AsnProp({ type: AsnPropTypes.Null })
    null?: any;
}


