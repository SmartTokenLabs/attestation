import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import {SignedDevconTicket} from "./SignedDevconTicket";
import {MyAttestation, SmartContract} from "./AttestationFramework";
import {UsageProof} from "./ProofOfExponentASN";

export class UseDevconTicket {

    @AsnProp({ type: SignedDevconTicket })
    public signedDevconTicket: SignedDevconTicket;

    @AsnProp({ type: MyAttestation })
    public attestation: MyAttestation;

    @AsnProp({ type: UsageProof })
    public proof: UsageProof;

    @AsnProp({ type: AsnPropTypes.BitString, optional: true })
    public signatureValue?: Uint8Array;

}
