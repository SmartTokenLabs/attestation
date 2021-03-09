import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {SubjectPublicKeyInfo} from "./AttestationFramework";
import {Proof} from "./ProofOfExponentASN";

// IdentifierType ::= INTEGER { email(0), phone(1)}

class IdentityPayload {

    @AsnProp({ type: AsnPropTypes.Integer })
    public type: number;

    @AsnProp({ type: Proof })
    public proof: Proof;

}

export class Identity {

    @AsnProp({ type: IdentityPayload })
    public identityPayload: IdentityPayload;

    @AsnProp({ type: SubjectPublicKeyInfo })
    public publicKey: SubjectPublicKeyInfo;

}


