import {ASNEncodable} from "./ASNEncodable";
import {Validateable} from "./Validateable";
import {SignedIdentifierAttestation} from "./SignedIdentifierAttestation";
import {ERC721Token} from "./ERC721Token";
import {Asn1Der} from "./DerUtility";
import {KeyPair} from "./KeyPair";
import {AsnParser} from "@peculiar/asn1-schema";
import {logger, uint8ToBn, uint8toBuffer, uint8tohex, uint8toString} from "./utils";
import {ERC721, NFTAttestationASN, Tokens} from "../asn1/shemas/NFTAttestation";
import {DEBUGLEVEL} from "../config";

export class NFTAttestation implements ASNEncodable, Validateable {
    private att: SignedIdentifierAttestation;
    private tokens: ERC721Token[];
    // private ASNtokens: ERC721;

    static fromAttAndTokens(att:SignedIdentifierAttestation, nftTokens: ERC721Token[])
    {
        let me = new this();
        me.att = att;
        me.tokens = nftTokens;

        return me;
    }

    private encodeTokens():string {
        let asn1: string = "";
        this.tokens.forEach( (nftToken:ERC721Token)=>{
            asn1 += Asn1Der.encode('SEQUENCE_30',nftToken.getTokenVector());
        })
        return Asn1Der.encode('SEQUENCE_30', asn1);
    }

    static fromAsnObj(NFTatt: NFTAttestationASN, identifierAttestationVerificationKey:KeyPair) {
        let me = new this();

        //root attestation, should be signed att
        me.att = SignedIdentifierAttestation.fromBytes(new Uint8Array( NFTatt.creator), identifierAttestationVerificationKey);

        me.tokens = [];

        NFTatt.tokens.forEach((token:ERC721)=>{
            me.tokens.push(ERC721Token.fromASNObj(token))
        })
        logger(DEBUGLEVEL.HIGH, me.tokens);

        return me;
    }

    static fromDer(asn1: Uint8Array, identifierAttestationVerificationKey:KeyPair) {
        try {
            return NFTAttestation.fromAsnObj(AsnParser.parse( uint8toBuffer(asn1), NFTAttestationASN), identifierAttestationVerificationKey);
        } catch (e){
            console.log(e);
            throw new Error('Cant parse NFTAttestationASN');
        }
    }

    public getDerEncoding():string {
        if (!this.tokens){
            logger(DEBUGLEVEL.LOW,"Empty tokens!!!");
            throw new Error("NFTs required for NFT attestaion");
        }
        let res = this.att.getDerEncoding() + this.encodeTokens();
        return Asn1Der.encode('SEQUENCE_30',res);
    }

    public getSignedIdentifierAttestation():SignedIdentifierAttestation {
        return this.att;
    }

    public getTokens():ERC721Token[] {
        return this.tokens;
    }

    // TODO type it
    public getSigningAlgorithm() {
        return this.att.getUnsignedAttestation().getSigningAlgorithm();
    }

    public checkValidity(): boolean {
        return this.att.checkValidity();
    }

    public verify(): boolean {
        return this.att.verify();
    }
}