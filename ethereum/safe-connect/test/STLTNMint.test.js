const { expect } = require('chai');
const { ethers } = require('hardhat');
const subtle = require("crypto").webcrypto.subtle;

const {EthereumKeyLinkingAttestation, SignedEthereumKeyLinkingAttestation} = require("@tokenscript/attestation/dist/asn1/shemas/EthereumKeyLinkingAttestation");
const {AsnParser, AsnSerializer} = require("@peculiar/asn1-schema");
const {AlgorithmIdentifierASN} = require("@tokenscript/attestation/dist/asn1/shemas/AuthenticationFramework");
const {EthereumAddressAttestation} = require("@tokenscript/attestation/dist/asn1/shemas/EthereumAddressAttestation");
const {LinkedAttestation, SignedLinkedAttestation} = require("@tokenscript/attestation/dist/asn1/shemas/SignedLinkedAttestation");
const {base64ToUint8array, hexStringToUint8, uint8arrayToBase64, uint8tohex} = require("@tokenscript/attestation/dist/libs/utils");
const {EpochTimeValidity} = require("@tokenscript/attestation/dist/asn1/shemas/EpochTimeValidity");
const {KeyPair} = require("@tokenscript/attestation/dist/libs/KeyPair");

describe("Mint test", function () {

    before(async function () {

        const [owner, addr1, addr2] = await ethers.getSigners();

        this.STLBayc = await ethers.getContractFactory('STLBayc');
        this.stlBayc = await (
            await this.STLBayc.deploy()
        ).deployed();

        console.log("Bayc contract constructed");

        await this.stlBayc.connect(addr1).safeMint(addr1.address, "https://gateway.pinata.cloud/ipfs/QmXdnWNa2CaRCUa4jMTirmkVJkygr2LtnccSuDY3yXrvVm/bayc_1013.json");

        console.log("Bayc tokens minted");

        this.STLTNMint = await ethers.getContractFactory('STLTNMint');
        this.stlTnMint = await (
            await this.STLTNMint.deploy(this.stlBayc.address)
        ).deployed();

        this.nftOwner = addr1;
        this.linkedAddress = addr2;

    });

    beforeEach(async function () {

    });

    it("Mint with attestation", async function () {

        let attestationHex = createAttestation(this.nftOwner.address, this.linkedAddress.address);

        let amount = 1000n * 1000000000000000000n;

        await ethers.provider.send('evm_setNextBlockTimestamp', [Math.round(Date.now() / 1000) + 60]);
        await ethers.provider.send('evm_mine');

        await expect(await this.stlTnMint.connect(this.linkedAddress).mintAttest(attestationHex, this.linkedAddress.address, amount)).to.not.throw;
    });

    it("Mint using signed challenge", async function () {

        let challenge = "Sign to prove ownership of 0x8646DF47d7b16Bf9c13Da881a2D8CDacDa8f5490 with SafeConnect (a6ti16iwPzyISrEgTXUJ5A==,1656596295)";
        //let signature = "0x2291e4b652c8d15ddecd5f0c9a22a54054162f47b65412e41376bf733a0f3a4a59691df1015ea92b8219d1b696952394887dc7f3d906334f80911b65a54709221b";

        let signature = await this.nftOwner.signMessage(challenge);

        let amount = 1000n * 1000000000000000000n;

        await expect(await this.stlTnMint.connect(this.nftOwner).mintSig(ethers.utils.toUtf8Bytes(challenge), signature, this.nftOwner.address, amount)).to.not.throw;
    });

    it("Mint directly", async function () {

        let amount = 1000n * 1000000000000000000n;

        await expect(await this.stlTnMint.connect(this.nftOwner).mint(this.nftOwner.address, amount)).to.not.throw;
    });


});

const HOLDING_KEY_ALGORITHM = "RSASSA-PKCS1-v1_5";

async function createAttestation(nftWallet, linkedWallet) {

    let privKeyStr = "7411181bdb51a24edd197bacda369830b1c89bbf872a4c2babbdd2e94f25d3b5";
    //let pubKeyStr = "0408d4bc48bc518c82fb4ad216ef88c11068b3f0c40ba60c255f9e0a7a18382e27654eee6b2283266071567993392c1a338fa0b9f2db7aaab1ba8bf2179808dd34";
    let attestorKeys = KeyPair.fromPrivateUint8(hexStringToUint8(privKeyStr), 'secp256k1');

    // Create a RSA keypair via subtle crypto API to be used by the 3rd party website.
    let attestHoldingKey = await subtle.generateKey(
        {
            name: HOLDING_KEY_ALGORITHM,
            modulusLength: 1024,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}
        },
        false,
        ["sign", "verify"]
    );

    let holdingPubKey = new Uint8Array(await subtle.exportKey("spki", attestHoldingKey.publicKey));

    let addressAttest = issueAndSignAddressAttestation(holdingPubKey, nftWallet, attestorKeys);

    return await createAndSignLinkAttestation(addressAttest, linkedWallet, attestHoldingKey.privateKey);
}

function issueAndSignAddressAttestation(holdingPubKey, attestedAddress, attestorKeys){

    const addressAttest = new SignedLinkedAttestation();
    addressAttest.attestation = new LinkedAttestation();
    addressAttest.attestation.ethereumAddress = new EthereumAddressAttestation();

    addressAttest.attestation.ethereumAddress.subjectPublicKey = holdingPubKey;

    addressAttest.attestation.ethereumAddress.validity = new EpochTimeValidity();
    addressAttest.attestation.ethereumAddress.validity.notBefore = Math.round((Date.now() / 1000));
    addressAttest.attestation.ethereumAddress.validity.notAfter = Math.round(((Date.now() / 1000) + 3600));

    addressAttest.attestation.ethereumAddress.ethereumAddress = hexStringToUint8(attestedAddress);

    const encodedAttest = AsnSerializer.serialize(addressAttest.attestation.ethereumAddress);

    console.log("Signing payload: " + uint8tohex(new Uint8Array(encodedAttest)));

    addressAttest.signingAlgorithm = new AlgorithmIdentifierASN();
    addressAttest.signingAlgorithm.algorithm = "1.2.840.10045.4.2"; // Our own internal identifier for ECDSA with keccak256
    addressAttest.signatureValue = hexStringToUint8(attestorKeys.signRawBytesWithEthereum(Array.from(new Uint8Array(encodedAttest))));

    const encodedAddressAttest = AsnSerializer.serialize(addressAttest);

    console.log("Constructed Address attestation: ");
    console.log(addressAttest);

    const base64AddressAttest = uint8arrayToBase64(new Uint8Array(encodedAddressAttest));

    console.log("Base64 encoded: " + base64AddressAttest);

    return base64AddressAttest;
}

async function createAndSignLinkAttestation(nftAttest, linkedEthAddress, holdingPrivKey){

    let linkedAttestObj = AsnParser.parse(base64ToUint8array(nftAttest), SignedLinkedAttestation);

    console.log("Decoded linked attestation");
    console.log(linkedAttestObj);

    const linkAttest = new SignedEthereumKeyLinkingAttestation();
    linkAttest.ethereumKeyLinkingAttestation = new EthereumKeyLinkingAttestation();
    linkAttest.ethereumKeyLinkingAttestation.subjectEthereumAddress = hexStringToUint8(linkedEthAddress);
    linkAttest.ethereumKeyLinkingAttestation.linkedAttestation = linkedAttestObj;

    linkAttest.ethereumKeyLinkingAttestation.validity = new EpochTimeValidity();
    linkAttest.ethereumKeyLinkingAttestation.validity.notBefore = Math.round(Date.now() / 1000);
    linkAttest.ethereumKeyLinkingAttestation.validity.notAfter = Math.round((Date.now() / 1000) + 3600);

    const linkAttestInfo = AsnSerializer.serialize(linkAttest.ethereumKeyLinkingAttestation);

    let linkSig;

    try {
        linkSig = await subtle.sign(
            {
                name: HOLDING_KEY_ALGORITHM,
                saltLength: 128,
            },
            holdingPrivKey,
            linkAttestInfo
        );
    } catch (e){
        console.log("Failed to sign:");
        console.log(e);
        throw e;
    }

    console.log("Signing payload:");
    console.log(uint8tohex(new Uint8Array(linkAttestInfo)));

    linkAttest.signingAlgorithm = new AlgorithmIdentifierASN();
    linkAttest.signingAlgorithm.algorithm = "1.2.840.113549.1.1.11"; // RSASSA pkcs1 v1.5 with SHA-256
    linkAttest.signatureValue = new Uint8Array(linkSig);

    const encodedLinkAttest = AsnSerializer.serialize(linkAttest);

    console.log("Constructed link attestation: ");
    console.log(linkAttest);

    const hexEncoded = uint8tohex(new Uint8Array(encodedLinkAttest));
    console.log("Hex encoded: ");
    console.log(hexEncoded);

    return "0x" + hexEncoded;
}