import {hexStringToArray} from "./utils";
import {KeyPair} from "./KeyPair";
import {ethers} from "ethers";
import {TypedDataUtils} from "eth-sig-util";
// let ethUtils = require("eth-sig-util");
// ethUtils.re
import {recoverPublicKey} from "ethers/lib/utils";
import {AttestationCrypto} from "./AttestationCrypto";

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');

let sha3 = require("js-sha3");

export interface Eip712DomainInterface {
    name: string,
    version: string,
    chainId?: number,
    verifyingContract?: string,
    salt?: string
}

export class SignatureUtility {
    // static Eip712Types: {[index: string]:string}  = {
    //     STRING: "string",
    //     BYTES32: "bytes32",
    //     UINT64: "uint64",
    //     UINT256: "uint256",
    //     ADDRESS: "address",
    // }

    static Eip712Data: {[index: string]:string}  = {
        PROTOCOL_VERSION: "0.1",
        JSON_RPC_VER: "2.0",
    }

    static Eip712domainTypes = [
        {name: "name", type: "string"},
        {name: "version", type: "string"},
        {name: "chainId", type: "uint256"},
        // {name: "verifyingContract", type: "address"},
        {name: "salt", type: "bytes32"},
    ];

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
        await window.ethereum.send('eth_requestAccounts');
        // let u = ethers.utils;
        let provider = new ethers.providers.Web3Provider(window.ethereum);
        let signer = provider.getSigner();
        return await signer.signMessage(message);
    }

    static async recoverPublicKeyFromMessageSignature(message: string, signature: string){

        const msgHash = ethers.utils.hashMessage(message);
        const digest = ethers.utils.arrayify(msgHash);

        return await ethers.utils.recoverPublicKey(digest, signature)
    }

    /*
    recover public key in format 0x042f196ec33ad04c6... 132chars
     */
    static recoverPublicKeyFromTypedMessageSignature(messageObj: any, signature: string): string {

        // console.log('messageObj');
        // console.log(messageObj);
        // console.log('JSON.stringify(messageObj)');
        // console.log(JSON.stringify(messageObj));
        // console.log('messageObj.types');
        // console.log(messageObj.types);

        // let rawPayload = messageObj.message.payload;
        // messageObj.message.payload = sha3.keccak256(rawPayload);

        let message, pubKey;
        try {
            let rawPayload = messageObj.message.payload;
            messageObj.message.payload = sha3.keccak256(rawPayload);
            message = TypedDataUtils.sign(messageObj);
            messageObj.message.payload = rawPayload;
        } catch (e){
            const m = 'Cant sign data, possibly wrong format. ' + e
            throw new Error(m);
        }

        try {
            pubKey = recoverPublicKey(message, signature);
        } catch (e){
            const m = 'Cant recoverPublicKey. ' + e;
            throw new Error(m);
        }

        return pubKey;
    }

    static async signEIP712WithBrowserWallet(webDomain: string, userDataValues: {[index: string]:string|number}, userDataTypes: Array<{name: string,type: string}>, primaryName: string): Promise<string> {
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
            if (!window.ethereum){
                throw new Error('Please install metamask before.');
            }

            const userAddresses = await window.ethereum.request({ method: 'eth_accounts' });
            if (!userAddresses){
                throw new Error("Active Wallet required");
            }

            // let u = ethers.utils;
            let provider = new ethers.providers.Web3Provider(window.ethereum);

            let signer = provider.getSigner();

            if (!signer) throw new Error("Active Wallet required");

            let network = await provider.getNetwork();

            // let ethAddress = await signer.getAddress();

            let Eip712Data = SignatureUtility.Eip712Data;

            // All properties on a domain are optional
            const domainData = {
                chainId: network.chainId,
                name: webDomain,
                // verifyingContract: '',
                salt: AttestationCrypto.generateRandomHexString(32), // 32-byte value
                version: Eip712Data['PROTOCOL_VERSION']
            };

            // The named list of all type definitions
            const dataTypes: { [index: string]: any } = {};
            dataTypes[primaryName] = userDataTypes;

            // hash payload string->hexString to make smaller message to sign
            let userDataValuesWithHashedPayload = Object.assign({}, userDataValues);
            userDataValuesWithHashedPayload.payload = sha3.keccak256(userDataValuesWithHashedPayload.payload);

            // this is internal logic, we can use it for debug
            /*
            console.log('lets try to sign data directly');
            const populated = await _TypedDataEncoder.resolveNames(domainData, dataTypes, userDataValues, (name: string) => {
                return window.ethereum.resolveName(name);
            });

            let typedMsg = _TypedDataEncoder.getPayload(populated.domain, dataTypes, populated.value);
            let msgParams = JSON.stringify(typedMsg);

            let directlySigned = await window.ethereum.send("eth_signTypedData_v4", [
                 userAddresses[0].toLowerCase(), msgParams
            ]);
            let signatureD = directlySigned.result;
            */

            let signature = await signer._signTypedData(domainData, dataTypes, userDataValuesWithHashedPayload);

            let completeData: { [index: string]: any } = {
                domain: domainData,
                message: userDataValues,
                primaryType: primaryName,
                types: {
                    EIP712Domain: SignatureUtility.Eip712domainTypes,
                }
            };

            completeData.types[primaryName] = dataTypes[primaryName];

            let dataStringified = JSON.stringify(completeData);
            let externalAuthenticationData: { [index: string]: string | number } = {
                signatureInHex: signature,
                jsonRpc: Eip712Data['JSON_RPC_VER'],
                chainId: network.chainId,
                jsonSigned: dataStringified
            };

            return JSON.stringify(externalAuthenticationData);
        } catch (e){
            console.error('Cant sign eip712 data. Error: '+ e);
            return '';
        }
    }

    static async connectMetamaskAndGetAddress(): Promise<string>{

        if (!window.ethereum){
            throw new Error('Please install metamask before.');
        }

        // const userAddresses = await window.ethereum.request({ method: 'eth_accounts' });
        const userAddresses = await window.ethereum.request({ method: 'eth_requestAccounts' });
        if (!userAddresses || !userAddresses.length ){
            throw new Error("Active Wallet required");
        }

        return userAddresses[0];
    }

    static getChainIdFromSignature(signature: string):number {
        let recoveryByte: number = Number("0x" + signature.substr(-2));
        if (recoveryByte == 27 || recoveryByte == 28) {
            return 0;
        }
        // recovery byte is chainId * 2 + 35 for chainId >= 1
        return (recoveryByte - 35) >> 1;
    }

    signDeterministicSHA256(toSign: Uint8Array, key: KeyPair) {
        let digest = AttestationCrypto.hashWithSHA256(toSign);
        let signature = this.computeInternalSignature(digest, key);
        return this.normalizeAndEncodeDerSignature(signature, key);
    }

    computeInternalSignature(digest: Uint8Array, key: KeyPair): bigint[]{
        let z: bigint = BigInt(digest);

        // TODO implement
        // HMacDSAKCalculator randomnessProvider = new HMacDSAKCalculator(new KeccakDigest(256));
        // randomnessProvider.init(key.getParameters().getN(), key.getD(), digest);
        //
        //
        // BigInteger n = key.getParameters().getN();
        // BigInteger r, k;
        // ECPoint R;
        // do {
        //     k = randomnessProvider.nextK();
        //     R = key.getParameters().getG().multiply(k).normalize();
        //     r = R.getAffineXCoord().toBigInteger().mod(n);
        // } while (r.equals(BigInteger.ZERO));
        // BigInteger baseS = k.modInverse(n).multiply(z.add(r.multiply(key.getD()))).mod(n);
        // BigInteger normalizedS = normalizeS(baseS, key.getParameters());
        // BigInteger v = R.getAffineYCoord().toBigInteger().mod(new BigInteger("2"));
        // // Normalize parity in case s needs normalization
        // if (!normalizedS.equals(baseS)) {
        //     // Flip the bit value
        //     v = BigInteger.ONE.subtract(v);
        // }
        // return new BigInteger[] {r, normalizedS, v};

        // throw Error because its not implemented
        throw new Error('Not implemeted computeInternalSignature');

    }

    normalizeAndEncodeDerSignature(signature: bigint[], params: any) {
        try {
            // TODO implement
            // ASN1EncodableVector asn1 = new ASN1EncodableVector();
            // asn1.add(new ASN1Integer(signature[0]));
            // BigInteger s = normalizeS(signature[1], params);
            // asn1.add(new ASN1Integer(s));
            // return new DERSequence(asn1).getEncoded();
            throw Error('not implemented')
        } catch (e) {
            throw new Error(e);
        }
    }

    normalizeS(s: bigint, params: any) {
        // TODO implement
        // Normalize number s to be the lowest of its two legal values
        // let half_curve: bigint = params.getCurve().getOrder().shiftRight(1);
        // if (s > half_curve) {
        //     return params.getN().subtract(s);
        // }
        // return s;

        throw Error('not implemented')
    }

    verifySHA256(unsigned: Uint8Array, signature: Uint8Array, key: KeyPair) {
        let digestBytes: Uint8Array = AttestationCrypto.hashWithSHA256(unsigned);
        return this.verifyHashed(digestBytes, signature, key);
    }

    verifyHashed(digest: Uint8Array, signature: Uint8Array, key: KeyPair) {
        // try {
        //     ASN1InputStream input = new ASN1InputStream(signature);
        //     ASN1Sequence seq = ASN1Sequence.getInstance(input.readObject());
        //     BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        //     BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        //     s = normalizeS(s, ((ECKeyParameters) key).getParameters());
        //     ECDSASigner signer = new ECDSASigner();
        //     signer.init(false, key);
        //     return signer.verifySignature(digest, r, s);
        // } catch (Exception e) {
        //     // Something went wrong so the signature cannot be verified
        //     return false;
        // }
        throw Error('not implemented')

    }
}
