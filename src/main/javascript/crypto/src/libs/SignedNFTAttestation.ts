import {ASNEncodable} from "./ASNEncodable";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {NFTAttestation} from "./NFTAttestation";
import {Signature} from "./Signature";
import {KeyPair} from "./KeyPair";
import {NFTAttestationASN} from "../asn1/shemas/NFTAttestation";
import {AsnParser} from "@peculiar/asn1-schema";
import {hexStringToUint8, logger, uint8toBuffer, uint8tohex} from "./utils";
import {SignedNFTAttestationASN} from "../asn1/shemas/SignedNFTAttestation";
import {CompressedMsgSignature} from "./CompressedMsgSignature";
import { PersonalSignature } from "./PersonalSignature";
import {Asn1Der} from "./DerUtility";
import {SignatureUtility} from "./SignatureUtility";
import {DEBUGLEVEL} from "../config";


export class SignedNFTAttestation implements ASNEncodable, Verifiable, Validateable {
    static DEFAULT_SIGNING_VERSION = 2;
    static PREFIX_MSG = "The digest of the ERC721 tokens for AlchemyNFT is: ";
    static POSTFIX_MSG = "";

    private att: NFTAttestation;
    private signingVersion: number;
    private signature: Signature;
    private attestationVerificationKey: KeyPair;

    static fromAtt(att:NFTAttestation, subjectSigningKey: KeyPair):SignedNFTAttestation {
        return SignedNFTAttestation.fromAttAndVer(att, subjectSigningKey, SignedNFTAttestation.DEFAULT_SIGNING_VERSION);
    }

    static fromAttAndVer(att: NFTAttestation, subjectSigningKey: KeyPair, signingVersion: number):SignedNFTAttestation {
        let me = new this();
        me.att = att;
        me.attestationVerificationKey = subjectSigningKey;
        me.signature =  me.makeSignatureWithKey(subjectSigningKey, signingVersion);

        me.signingVersion = signingVersion;
        if (!me.verify()) {
            throw new Error("The signature is not valid");
        }
        return me;
    }

    /**
     * Constructor used for when we supply the signature separately
     */
    static fromAttAndSign( att: NFTAttestation, signature: Signature) {
        let me = new this();
        me.att = att;
        me.attestationVerificationKey = me.getKeyFromAttestation();
        me.signature = signature;
        me.signingVersion = me.determineSigningVersion();
        if (!me.verify()) {
            throw new Error("The signature is not valid");
        }
        return me;
    }

    static fromASN(asn1: Uint8Array, identifierAttestationVerificationKey: KeyPair) {
        let me = new this();
        let sNFTatt: SignedNFTAttestationASN;
        try {
            sNFTatt = AsnParser.parse( uint8toBuffer(asn1), SignedNFTAttestationASN);
        } catch (e){
            throw new Error('Cant parse SignedNFTAttestationASN');
        }
        me.att = NFTAttestation.fromAsnObj(sNFTatt.nftAttestation, identifierAttestationVerificationKey);
        if (sNFTatt.signingVersion) {
            me.signingVersion = sNFTatt.signingVersion;
        } else {
            // If signingVersion is not present we default to version 1
            me.signingVersion = 1;
        }
        // todo this actually not used
        // AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(asn1.getObjectAt(currentPos++));
        // DERBitString signatureEnc = DERBitString.getInstance(asn1.getObjectAt(currentPos++));
        me.signature = me.makeSignature(new Uint8Array(sNFTatt.signatureValue), me.signingVersion);
        me.attestationVerificationKey = me.getKeyFromAttestation();
        return me;
    }

    private determineSigningVersion():number {
        if (this.signature instanceof PersonalSignature) {
            return 1;
        }
        else if (this.signature instanceof CompressedMsgSignature) {
            return 2;
        } else {
            throw new Error("Unexpected signature type used");
        }
    }

    public makeSignature(encodedBytes: Uint8Array, signingVersion: number): Signature {
        if (signingVersion == 1) {
            let res = new PersonalSignature();
            res.fromSignature(uint8tohex(encodedBytes));
            return res;
        }
        else if (signingVersion == 2) {
            let res = new CompressedMsgSignature();
            res.fromRawSignatureAndPrefix(uint8tohex(encodedBytes), SignedNFTAttestation.PREFIX_MSG, SignedNFTAttestation.POSTFIX_MSG );
            return res;
        } else {
            throw new Error("Unknown signing version");
        }
    }

    public makeSignatureWithKey(key: KeyPair, signingVersion: number):Signature {
        if (signingVersion == 1) {
            let res = new PersonalSignature();
            res.fromMessage(key, hexStringToUint8(this.att.getDerEncoding()));
            return res;
        }
        else if (signingVersion == 2) {
            let res = new CompressedMsgSignature();
            res.fromKeyMessagePrefix(key, hexStringToUint8(this.att.getDerEncoding()), SignedNFTAttestation.PREFIX_MSG, SignedNFTAttestation.POSTFIX_MSG);
            return res;
        } else {
            throw new Error("Unknown signing version");
        }
    }

    private getKeyFromAttestation(): KeyPair {
        return this.att.getSignedIdentifierAttestation().getUnsignedAttestation()
                    .getSubjectPublicKeyInfo();
    }

    public getUnsignedAttestation(): NFTAttestation {
        return this.att;
    }

    public getSignature():Signature {
        return this.signature;
    }

    /**
     * Returns the public key of the attestation signer
     */
    public getAttestationVerificationKey(): KeyPair {
        return this.attestationVerificationKey;
    }

    public getDerEncoding(): string {
        return SignedNFTAttestation.constructSignedAttestation(this.att, this.signingVersion, this.signature.getRawSignature());
    }

    static constructSignedAttestation( unsignedAtt:NFTAttestation, signingVersion: number, signature: string): string {

        let res = unsignedAtt.getDerEncoding()
        + (signingVersion > 1 ? Asn1Der.encode('INTEGER', signingVersion): "")
        + Asn1Der.encodeObjectId(unsignedAtt.getSigningAlgorithm())
        + Asn1Der.encode('BIT_STRING', signature);

        return Asn1Der.encode('SEQUENCE_30', res);
    }

    public checkValidity():boolean {
        return this.getUnsignedAttestation().checkValidity();
    }

    public verify():boolean {
        if (!this.signature.verify(hexStringToUint8(this.att.getDerEncoding()), this.attestationVerificationKey)) {
            logger(DEBUGLEVEL.MEDIUM, `Signature verify failed for address: ${this.attestationVerificationKey.getAddress()} and derEncoded: ${this.att.getDerEncoding()} and signature = ${this.signature.getRawSignature()}` );
            return false;
        }
        if (!this.att.verify()) {
            logger(DEBUGLEVEL.LOW, "Att verify failed");
            return false;
        }
        // Verify that signature is done using thew right key
        if (this.attestationVerificationKey.getAddress() != this.getKeyFromAttestation().getAddress()) {
            logger(DEBUGLEVEL.LOW, "Keys doesnt fit");

            return false;
        }
        return true;
    }
}