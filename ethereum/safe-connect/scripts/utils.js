const subtle = require("crypto").webcrypto.subtle;

const { EthereumKeyLinkingAttestation, SignedEthereumKeyLinkingAttestation } = require("@tokenscript/attestation/dist/asn1/shemas/EthereumKeyLinkingAttestation");
const { AsnParser, AsnSerializer } = require("@peculiar/asn1-schema");
const { AlgorithmIdentifierASN } = require("@tokenscript/attestation/dist/asn1/shemas/AuthenticationFramework");
const { EthereumAddressAttestation } = require("@tokenscript/attestation/dist/asn1/shemas/EthereumAddressAttestation");
const { LinkedAttestation, SignedLinkedAttestation } = require("@tokenscript/attestation/dist/asn1/shemas/SignedLinkedAttestation");
const { base64ToUint8array, hexStringToUint8, uint8arrayToBase64, uint8tohex } = require("@tokenscript/attestation/dist/libs/utils");
const { EpochTimeValidity } = require("@tokenscript/attestation/dist/asn1/shemas/EpochTimeValidity");
const { KeyPair } = require("@tokenscript/attestation/dist/libs/KeyPair");
const { ATTESTOR_PRIV_KEY } = require("./constants");

const HOLDING_KEY_ALGORITHM = "RSASSA-PKCS1-v1_5";

async function createAttestation(nftWallet, linkedWallet) {

  let privKeyStr = ATTESTOR_PRIV_KEY;
  //let pubKeyStr = "0408d4bc48bc518c82fb4ad216ef88c11068b3f0c40ba60c255f9e0a7a18382e27654eee6b2283266071567993392c1a338fa0b9f2db7aaab1ba8bf2179808dd34";
  let attestorKeys = KeyPair.fromPrivateUint8(hexStringToUint8(privKeyStr), 'secp256k1');

  // Create a RSA keypair via subtle crypto API to be used by the 3rd party website.
  let attestHoldingKey = await subtle.generateKey(
    {
      name: HOLDING_KEY_ALGORITHM,
      modulusLength: 1024,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    // publicExponent: new Uint8Array([0x00, 0x00, 0x03]),
      hash: { name: "SHA-256" }
    },
    false,
    ["sign", "verify"]
  );

  let holdingPubKey = new Uint8Array(await subtle.exportKey("spki", attestHoldingKey.publicKey));

  let addressAttest = issueAndSignAddressAttestation(holdingPubKey, nftWallet, attestorKeys);

  return await createAndSignLinkAttestation(addressAttest, linkedWallet, attestHoldingKey.privateKey);
}

function issueAndSignAddressAttestation(holdingPubKey, attestedAddress, attestorKeys) {

  const addressAttest = new SignedLinkedAttestation();
  addressAttest.attestation = new LinkedAttestation();
  addressAttest.attestation.ethereumAddress = new EthereumAddressAttestation();

  addressAttest.attestation.ethereumAddress.subjectPublicKey = holdingPubKey;

  addressAttest.attestation.ethereumAddress.validity = new EpochTimeValidity();
  addressAttest.attestation.ethereumAddress.validity.notBefore = Math.round((Date.now() / 1000));
  addressAttest.attestation.ethereumAddress.validity.notAfter = Math.round(((Date.now() / 1000) + 3600));

  addressAttest.attestation.ethereumAddress.ethereumAddress = hexStringToUint8(attestedAddress);

  const encodedAttest = AsnSerializer.serialize(addressAttest.attestation.ethereumAddress);

  addressAttest.signingAlgorithm = new AlgorithmIdentifierASN();
  addressAttest.signingAlgorithm.algorithm = "1.3.132.0.10"; // secp256k1
  addressAttest.signatureValue = hexStringToUint8(attestorKeys.signRawBytesWithEthereum(Array.from(new Uint8Array(encodedAttest))));

  const encodedAddressAttest = AsnSerializer.serialize(addressAttest);

  const base64AddressAttest = uint8arrayToBase64(new Uint8Array(encodedAddressAttest));

  return base64AddressAttest;
}

async function createAndSignLinkAttestation(nftAttest, linkedEthAddress, holdingPrivKey) {
  let linkedAttestObj = AsnParser.parse(base64ToUint8array(nftAttest), SignedLinkedAttestation);

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
  } catch (e) {
    console.log("Failed to sign:", e);
    throw e;
  }

  linkAttest.signingAlgorithm = new AlgorithmIdentifierASN();
  linkAttest.signingAlgorithm.algorithm = "2.16.840.1.101.3.4.3.14"; // RSASSA pkcs1 v1.5 with SHA 256
  linkAttest.signatureValue = new Uint8Array(linkSig);

  const encodedLinkAttest = AsnSerializer.serialize(linkAttest);

  const hexEncoded = uint8tohex(new Uint8Array(encodedLinkAttest));

  return "0x" + hexEncoded;
}

module.exports = {
  createAttestation
}
