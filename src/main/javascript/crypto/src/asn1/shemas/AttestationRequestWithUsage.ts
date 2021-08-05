import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";

import {Proof} from "./ProofOfExponentASN";
import {PublicKeyInfoValue} from "./AttestationFramework";

// IdentifierType ::= INTEGER { email(0), phone(1)}

export class Identifier {

    @AsnProp({ type: AsnPropTypes.Integer })
    public type: number;

    @AsnProp({ type: Proof })
    public proof: Proof;

    @AsnProp({ type: PublicKeyInfoValue })
    public sessionKey: PublicKeyInfoValue;

}


