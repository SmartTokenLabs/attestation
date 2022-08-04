const subtle = require("crypto").webcrypto.subtle;

const { EthereumKeyLinkingAttestation } = require("@tokenscript/attestation/dist/safe-connect/EthereumKeyLinkingAttestation");
const { EthereumAddressAttestation } = require("@tokenscript/attestation/dist/safe-connect/EthereumAddressAttestation");
const { hexStringToUint8, uint8tohex } = require("@tokenscript/attestation/dist/libs/utils");
const { KeyPair } = require("@tokenscript/attestation/dist/libs/KeyPair");
const { ATTESTOR_PRIV_KEY } = require("./constants");
const {NFTOwnershipAttestation} = require("@tokenscript/attestation/dist/safe-connect/NFTOwnershipAttestation");

const HOLDING_KEY_ALGORITHM = "RSASSA-PKCS1-v1_5";

async function createAttestation(nftWalletOrNfts, linkedWallet, validity, validFrom) {

    if (!validity)
        validity = 3600;

    if (!validFrom)
        validFrom = Math.round(Date.now() / 1000) - 1800;

    let attestorKeys = KeyPair.fromPrivateUint8(hexStringToUint8(ATTESTOR_PRIV_KEY), 'secp256k1');

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

    let base64Attest;

    if (typeof nftWalletOrNfts === "string"){

        const attestation = new EthereumAddressAttestation();
        attestation.create(holdingPubKey, nftWalletOrNfts, attestorKeys, validity, validFrom);
        base64Attest = attestation.getBase64();

    } else {

        const attestation = new NFTOwnershipAttestation();
        attestation.create(holdingPubKey, nftWalletOrNfts.contract, nftWalletOrNfts.chain, attestorKeys, validity, validFrom);
        base64Attest = attestation.getBase64();
    }


    const linkAttest = new EthereumKeyLinkingAttestation();

    linkAttest.create(base64Attest, linkedWallet, validity, validFrom);
    await linkAttest.sign(attestHoldingKey.privateKey);

    const hexEncoded = uint8tohex(linkAttest.getEncoded());

    return "0x" + hexEncoded;
}

module.exports = {
  createAttestation
}
