import {ASNEncodable} from "./ASNEncodable";
import {AsnParser} from "@peculiar/asn1-schema";
import {bnToUint8, uint8ToBn, uint8tohex} from "./utils";
import {ERC721} from "../asn1/shemas/NFTAttestation";
import {Asn1Der} from "./DerUtility";

export class ERC721Token implements ASNEncodable {
    private encoding: string;
    private address: string;
    private tokenId: bigint;

    static fromStrings(address:string, tokenId:string) {
        let me = new this();
        // remove 0x
        me.address = address.toLowerCase().substring(2);
        let tokenIdInteger: bigint;
        try {
            tokenIdInteger = BigInt(tokenId);
        } catch (e) {
            tokenIdInteger = 0n;
        }
        me.validateID(tokenIdInteger);
        me.tokenId = tokenIdInteger;
        me.encoding = me.constructEncoding();
        return me;
    }

    public fromStringAndBigint(address:string, tokenId:bigint) {
        this.address = address.toLowerCase();
        this.validateID(tokenId);
        this.tokenId = tokenId;
        this.encoding = this.constructEncoding();
    }

    private validateID(tokenId: bigint) {
        // Only allow non-negative IDs
        if (tokenId < 0n) {
            throw new Error("IDs cannot be negative");
        }
    }

    static fromBytes(asn1: Uint8Array) {
        try {
            let token = AsnParser.parse(asn1, ERC721);
            return ERC721Token.fromASNObj(token);
        } catch (e){
            throw new Error('Cant parse AttestationRequest Identifier');
        }
    }

    static fromASNObj(token: ERC721): ERC721Token {
        let me = new this();
        // Remove the # added by BouncyCastle
        //this.address = address.toString().substring(1);
        me.address = uint8tohex(new Uint8Array(token.address));
        me.tokenId = uint8ToBn(new Uint8Array(token.tokenId));
        me.encoding = me.constructEncoding();

        return me;
    }

    public getAddress():string {
        return this.address;
    }

    public getTokenId(): bigint {
        return this.tokenId;
    }

    public getDerEncoding(): string
    {
        return this.encoding;
    }

    public constructEncoding(): string {
        try {
            return Asn1Der.encode('SEQUENCE_30',this.getTokenVector());
        } catch (e) {
            throw new Error(e);
        }
    }
    public getTokenVector():string {
        return Asn1Der.encode('OCTET_STRING',this.address) +
            Asn1Der.encode('OCTET_STRING',uint8tohex(bnToUint8(this.tokenId)));
    }
}