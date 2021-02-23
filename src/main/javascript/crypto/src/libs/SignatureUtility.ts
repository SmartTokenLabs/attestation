import {bnToUint8, hexStringToArray, uint8toBuffer, uint8tohex} from "./utils";
import {KeyPair} from "./KeyPair";
import {ethers} from "ethers";
import {AttestationCrypto} from "./AttestationCrypto";
import {MyAttestation} from "../asn1/shemas/AttestationFramework";
import {AsnParser} from "@peculiar/asn1-schema";
import {Signature} from "../asn1/shemas/Signature";
let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

let sha3 = require("js-sha3");

export class SignatureUtility {
    static Eip712Types: {[index: string]:string}  = {
        STRING: "string",
        BYTES32: "bytes32",
        UINT64: "uint64",
        UINT256: "uint256",
        ADDRESS: "address",
    }
    static Eip712Data: {[index: string]:string}  = {
        PRIMARY_NAME: "Authentication",
        DESCRIPTION_NAME: "description",
        PAYLOAD_NAME: "payload",
        TIMESTAMP_NAME: "timestamp",
        USAGE_VALUE: "Single-use authentication",
        PROTOCOL_VERSION: "0.1",
        JSON_RPC_VER: "2.0",
    }
    static sign(str: string, keys: KeyPair):string {
        let ecKey = ec.keyFromPrivate(keys.getPrivateAsHexString(), 'hex');
        let encodingHash = sha3.keccak256(hexStringToArray(str))
        let signature = ecKey.sign(encodingHash);
        return signature.toDER('hex');
    }

    static verify(str: string, signature: string, keys: KeyPair):boolean {
        return SignatureUtility.verifyArrayBuf(hexStringToArray(str), signature, keys);
    }

    static verifyArrayBuf(arr: ArrayBuffer|Uint8Array|number[], signature: string, keys: KeyPair):boolean {
        let ecKey = ec.keyFromPublic(keys.getPublicKeyAsHexStr(), 'hex');
        let encodingHash = sha3.keccak256(arr)
        return ecKey.verify(encodingHash, signature);
    }

    static async signMessageWithBrowserWallet(message: string){
        await window.ethereum.enable();
        // let u = ethers.utils;
        let provider = new ethers.providers.Web3Provider(window.web3.currentProvider);
        let signer = provider.getSigner();
        return await signer.signMessage(message);
    }

    static async recoverPublicKeyFromMessageSignature(message: string, signature: Uint8Array){
        // await window.ethereum.enable();
        // let u = ethers.utils;
        // let provider = new ethers.providers.Web3Provider(window.web3.currentProvider);
        // let signer = provider.getSigner();

        const msgHash = ethers.utils.hashMessage(message);
        const digest = ethers.utils.arrayify(msgHash);

        const signObj: Signature = AsnParser.parse( uint8toBuffer( signature ), Signature);
        console.log(signObj);
        let joinSignHex = '0x' + uint8tohex(bnToUint8(signObj.r)).padStart(64,'0') + uint8tohex(bnToUint8(signObj.s)).padStart(64,'0');

        let sign = ethers.utils.splitSignature(joinSignHex);
        // var m = signature.match(/([a-f\d]{64})/gi);

        // let sign = {
        //     r: m[0],
        //     s: m[1]
        // };
        return await ethers.utils.recoverPublicKey(digest, sign)
    }

    static async signEIP712WithBrowserWallet(payload: string, webDomain: string){
        // How its encoded at metamask ...
        // All properties on a domain are optional
        // const domain = {
        //     name: 'Devcon Ticket',
        //     version: '1',
        //     chainId: 3,
        //     verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        //     salt: "0x64656667646667657267657274796a74796a6231000000000000000000000000" // 32-byte value
        // };
        // const data = JSON.stringify({
        //     types: {
        //         EIP712Domain: domain,
        //         Bid: bid,
        //         Identity: identity,
        //     },
        //     domain: domainData,
        //     primaryType: "Bid",
        //     message: message
        // });
        // web3.currentProvider.sendAsync(
        // {
        //     method: "eth_signTypedData_v3",
        //     params: [signer, data],
        //     from: signer
        // },
        try {
            await window.ethereum.enable();
            // let u = ethers.utils;
            let provider = new ethers.providers.Web3Provider(window.web3.currentProvider);
            let signer = provider.getSigner();
            let network = await provider.getNetwork();

            // let ethAddress = await signer.getAddress();

            let Eip712Data = SignatureUtility.Eip712Data;
            let Eip712Types = SignatureUtility.Eip712Types;

            const domainTypes = [
                {name: "name", type: "string"},
                {name: "version", type: "string"},
                {name: "chainId", type: "uint256"},
                {name: "verifyingContract", type: "address"},
                {name: "salt", type: "bytes32"},
            ];

            // All properties on a domain are optional
            const domainData = {
                name: webDomain,
                version: Eip712Data['PROTOCOL_VERSION'],
                chainId: network.chainId,
                //salt: "0x64656667646667657267657274796a74796a6231000000000000000000000000" // 32-byte value
                salt: AttestationCrypto.generateRandomHexString(32) // 32-byte value
            };

            // The named list of all type definitions
            const dataTypes: { [index: string]: any } = {};
            dataTypes[Eip712Data['PRIMARY_NAME']] = [
                {name: Eip712Data['PAYLOAD_NAME'], type: 'string'},
                {name: Eip712Data['DESCRIPTION_NAME'], type: 'string'},
                {name: Eip712Data['TIMESTAMP_NAME'], type: 'uint256'},
            ];

            // The data to sign
            const dataValue: { [index: string]: string | number } = {};
            dataValue[Eip712Data['PAYLOAD_NAME']] = payload;
            dataValue[Eip712Data['DESCRIPTION_NAME']] = Eip712Data['USAGE_VALUE'];
            dataValue[Eip712Data['TIMESTAMP_NAME']] = (new Date()).getTime();

            let signature = await signer._signTypedData(domainData, dataTypes, dataValue);

            let completeData: { [index: string]: any } = {
                types: {
                    EIP712Domain: domainTypes,
                },
                domain: domainData,
                primaryType: Eip712Data['PRIMARY_NAME'],
                message: dataValue
            };
            completeData.types[Eip712Data['PRIMARY_NAME']] = dataTypes;

            let dataStringified = JSON.stringify(completeData);

            let externalAuthenticationData: { [index: string]: string | number } = {
                signatureInHex: signature,
                jsonRpc: Eip712Data['JSON_RPC_VER'],
                chainId: network.chainId,
                jsonSigned: dataStringified,
            };

            return JSON.stringify(externalAuthenticationData);
        } catch (e){
            console.error('Cant sign eip712 data. Error: '+ e);
            return false;
        }
    }
}
