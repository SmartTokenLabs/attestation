// import {} from "@tokenscript/attestation";
import {EasTicketAttestation, TicketSchema} from "@tokenscript/attestation/dist/eas/EasTicketAttestation";
import {base64toBase64Url} from "@tokenscript/attestation/dist/libs/utils";
import {KeyPair} from "@tokenscript/attestation/dist/libs/KeyPair";
import {hexStringToUint8} from "@tokenscript/attestation/dist/libs/utils";
import {ethers} from "ethers";

const EAS_CONFIGS = {
    "0.26": {
        sepolia: {
            address: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",// Sepolia v0.26
            // shemaContract: "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
            version: "0.26",
            chainId: 11155111,
            rpc: ["https://rpc.sepolia.org","https://rpc2.sepolia.org","https://rpc-sepolia.rockx.com"]
        },
        ethereum: {
            address: "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",// Sepolia v0.26
            // shemaContract: "0xA7b39296258348C78294F95B872b282326A97BDF",
            version: "0.26",
            chainId: 1,
            rpc: ["https://mainnet.infura.io/v3/${INFURA_API_KEY}","wss://mainnet.infura.io/ws/v3/${INFURA_API_KEY}","https://api.mycryptoapi.com/eth","https://cloudflare-eth.com","https://ethereum.publicnode.com"]
        },
        arbitrumOne: {
            address: "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",// Sepolia v0.26
            // shemaContract: "0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB",
            version: "0.26",
            chainId: 42161,
            rpc: ["https://arbitrum-mainnet.infura.io/v3/${INFURA_API_KEY}","https://arb-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}","https://arb1.arbitrum.io/rpc"]
        }
    },
    "0.27": {
        optimismGoerli: {
            address: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",// Sepolia v0.26
            // shemaContract: "0x7b24C7f8AF365B4E308b6acb0A7dfc85d034Cb3f",
            version: "0.27",
            chainId: 420,
            rpc:["https://goerli.optimism.io/"]
        },
        baseGoerli: {
            address: "0xAcfE09Fd03f7812F022FBf636700AdEA18Fd2A7A",// Sepolia v0.26
            // shemaContract: "0x720c2bA66D19A725143FBf5fDC5b4ADA2742682E",
            version: "0.27",
            chainId: 84531,
            rpc:["https://goerli.base.org"]
        }
    }
};

const EAS_TICKET_SCHEMA: TicketSchema = {
	fields: [
		{ name: "devconId", type: "string" },
		{ name: "ticketIdString", type: "string" },
		{ name: "ticketClass", type: "uint8",  },
		{ name: "commitment", type: "bytes", isCommitment: true },
	]
};

let version;
let networkName = "";
let wallet;
let selectedNetwork;
let conferenceId = "";
let issuerPrivKey:KeyPair;
let rpc;
let rpcData = {}
const pubKeyConfig = {};
let easAttest;

async function issue(){

    let tokenId = "";
    let tokenClass = "";
    let ticketAttestationEmail = "";
    let validityFrom = "";
    let validityTo = "";

    // [,,,,,,,ticketAttestationEmail, tokenId, tokenClass, validityFrom, validityTo] = process.argv;
    [,,,,,,,ticketAttestationEmail, tokenId, tokenClass, validityTo, validityFrom] = process.argv;
    
    let ticketBase64;
    let ticketSecret;

    tokenClass = tokenClass ? tokenClass : "0"

    try {
        let options = {};
        if (validityFrom || validityTo){
            let validity = {}
            validityFrom && (validity["from"] = validityFrom)
            validityTo && (validity["to"] = validityTo)
            options = {validity};
        }
        await easAttest.createEasAttestation({
            devconId: conferenceId,
            ticketIdString: tokenId,
            ticketClass: tokenClass,
            commitment: ticketAttestationEmail,
        }, options);

        ticketBase64 = easAttest.getEncoded();
        ticketSecret = easAttest.getEasJson().secret;
    } catch(e){
        throw new Error(`Attestation build error "${e.message}"`)
    }
    
    if (!ticketSecret){
        throw new Error("Ticket secret undefined!");
    }
    if (!ticketBase64){
        throw new Error("Ticket build failed!");
    }

    return `?type=eas&ticket=${base64toBase64Url(ticketBase64)}&secret=${ticketSecret?.toString()}&id=${encodeURIComponent(ticketAttestationEmail)}`;
}

async function verify(){
    let encoded;
    
    [,,,,,,,encoded] = process.argv;

    try {
        easAttest.loadFromEncoded( encoded, pubKeyConfig);
    } catch(e){
        throw new Error("EAS Attestation broken")
    }

    let decoded = await decodeAttestation();
    try {        
        await easAttest.validateEasAttestation();  
        decoded["valid"] = true
    } catch(e){
        decoded["valid"] = false
    }

    return decoded
}

async function revoke(){

    let decoded = await verify();

    if (!decoded["valid"]){
        return decoded;
    }
    try {
        await easAttest.revokeEasAttestation();
    } catch {
        throw new Error("Revoke Error")
    }

    decoded = await verify();

    if (decoded["valid"]){
        throw new Error("Attestation not revoked")
    }
    return decoded;
}

async function decodeAttestation(){
    let json = easAttest.getEasJson();

    let defaultAbiCoder = new ethers.utils.AbiCoder();

    const abiDecoded = defaultAbiCoder.decode(EAS_TICKET_SCHEMA.fields.map(key => key.type), json.sig.message.data);

    let payload = {}
    EAS_TICKET_SCHEMA.fields.forEach((key,index) => { payload[key.name] = abiDecoded[index]} )
    
    return {
        uid: json.sig.uid,
        time: json.sig.message.time,
        expirationTime: json.sig.message.expirationTime,
        payload,
        revocable: json.sig.message.revocable,
        signer: json.signer
    };
}

(async () => {

    let action = "";
    let privateKey = "";

    [,,action,networkName,version,conferenceId,privateKey] = process.argv;

    let output ;
    try {

        // issuerPrivKey = KeyPair.privateFromPEM(privateKey);
        issuerPrivKey = KeyPair.fromPrivateUint8(hexStringToUint8(privateKey), "secp256k1");

        if (!EAS_CONFIGS[version]) throw new Error(`Unknown EAS version '${version}'`)

        if (!EAS_CONFIGS[version][networkName]) throw new Error(`Unknown network '${networkName}'`)

        selectedNetwork = EAS_CONFIGS[version][networkName]

        let currentRpcIndex = 0;
        let balance;
        for (currentRpcIndex = 0; currentRpcIndex < selectedNetwork.rpc.length; currentRpcIndex++){
            let currentRpc = selectedNetwork.rpc[currentRpcIndex]
            try {
                const provider = new ethers.providers.JsonRpcProvider(currentRpc)
                wallet = new ethers.Wallet(issuerPrivKey.getPrivateAsHexString(), provider)
                // balance = await provider.getBalance(wallet.address)
                rpc = currentRpc;
                break;
            } catch(e){}
        }
        rpc = selectedNetwork.rpc[0]

        if (!rpc) throw new Error("Cant connect to RPC")
                
        pubKeyConfig[conferenceId] = issuerPrivKey;
        
        rpcData[selectedNetwork.chainId] = rpc;
        
        easAttest = new EasTicketAttestation(EAS_TICKET_SCHEMA, {EASconfig:selectedNetwork,signer: wallet}, rpcData);

        switch (action){
            case "issue":
                // let params = await issue();
                output = {success: true, data: await issue()}
                break;
            case "verify":
                output = {success: true, data: await verify()}
                break;
            case "revoke":
                output = {success: true, data: await revoke()}
                break;
            default:
                throw new Error(`Unknown action: "${action}"`)
        }
        // output["balance"] = balance.toHexString()
    } catch(e){
        console.log("error...", action)
        output = {success: false, data: e.message}
    }
    console.log(JSON.stringify(output))
        
})()