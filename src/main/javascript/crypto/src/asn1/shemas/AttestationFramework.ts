import {AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";
import { ValidityValue, Version, AlgorithmIdentifier } from "./AuthenticationFramework";
import {Name} from "./InformationFramework";

export class SubjectPublicKeyInfoValue {
    @AsnProp({ type: AlgorithmIdentifier }) public algorithm: SubjectPublicKeyInfoValue;
    @AsnProp({ type: AsnPropTypes.Any }) public subjectPublicKey: AsnPropTypes.BitString;
}

@AsnType({ type: AsnTypeTypes.Choice })
export class SubjectPublicKeyInfo {
    @AsnProp({ type: SubjectPublicKeyInfoValue }) public value: SubjectPublicKeyInfoValue;
    @AsnProp({ type: AsnPropTypes.Any }) public null? = false;
}

class SignedInfo {
    @AsnProp({ type: Version }) public version: Version; // [0]  EXPLICIT Version,
    // @AsnProp({ type: AsnPropTypes.Any }) public serialNumber: any; // CertificateSerialNumber,
    @AsnProp({ type: AsnPropTypes.Integer }) public serialNumber: number; // CertificateSerialNumber,
    @AsnProp({ type: AlgorithmIdentifier }) public signature: AlgorithmIdentifier; // AlgorithmIdentifier,
    // @AsnProp({ type: AsnPropTypes.Any }) public signature: any; // AlgorithmIdentifier,
    // @AsnProp({ type: AsnPropTypes.Any }) public issuer: AsnPropTypes.Any; // Name,
    @AsnProp({ type: Name }) public issuer:Name; // Name,
    @AsnProp({ type: ValidityValue }) public validity:ValidityValue; // Validity,
    // @AsnProp({ type: AsnPropTypes.Any }) public subject = false; //  Name,
    @AsnProp({ type: Name }) public subject: Name; //  Name,
    @AsnProp({ type: SubjectPublicKeyInfo }) public subjectPublicKeyInfo: SubjectPublicKeyInfo; // SubjectPublicKeyInfo,
    // TODO handle optional field
    // @AsnProp({ type: AsnPropTypes.Any }) public contract = false; // contract             SEQUENCE OF SmartContract OPTIONAL,
    @AsnProp({ type: AsnPropTypes.Any }) public attestsTo = false; //attestsTo         CHOICE {
    //             extensions        [3] EXPLICIT Extensions,
    //             dataObject        [4] DataObject -- defined per objectClass
    //     }
}

export class MyAttestation {
    // @AsnProp({ type: AsnPropTypes.Any }) public signedInfo: Uint8Array = new Uint8Array();
    @AsnProp({ type: SignedInfo }) public signedInfo = false;
    @AsnProp({ type: AlgorithmIdentifier }) public signatureAlgorithm: AlgorithmIdentifier;
    @AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: AsnPropTypes.BitString;
}
