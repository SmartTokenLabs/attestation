const { expect } = require('chai');
const { ethers } = require('hardhat');

const { ATTESTOR_ADDRESS, SENDING_ADDRESS } = require("../scripts/constants");
const { createAttestation } = require('../scripts/utils');
const { uint8tohex } = require("@tokenscript/attestation/dist/libs/utils");
const {readFileSync} = require("fs");
const {KeyPair} = require("@tokenscript/attestation/dist/libs/KeyPair");
const {EthereumKeyLinkingAttestation} = require("@tokenscript/attestation/dist/safe-connect/EthereumKeyLinkingAttestation");
const PREFIX_PATH = "../../build/test-results/";

describe("Verify Address Attestation", function () {
    before(async function () {

        await hre.network.provider.send("hardhat_reset");
        await ethers.provider.send('evm_setNextBlockTimestamp', [Math.round(Date.now() / 1000)]);

        let libFactory = await ethers.getContractFactory("LinkAttestUtils");
        let libObj = await libFactory.deploy();

        this.VerifyAddressAttestationTest = await ethers.getContractFactory('VerifyAddressAttestationTest', {
            libraries: {
                LinkAttestUtils: libObj.address,
            },
        });

        this.VerifyAddressAttestationTest = await (
            await this.VerifyAddressAttestationTest.deploy()
        ).deployed();

        this.signers = await ethers.getSigners();

    });

    beforeEach(async function () {

    });

    it("Javascript generated attestation should be valid", async function () {
        let attestorAddress = ATTESTOR_ADDRESS;

        let sendingAddress = SENDING_ADDRESS;

        console.log("create attestation");

        let attestationHex = await createAttestation(
            this.signers[0].address, // NFT owner wallet
            sendingAddress // linked address
        ).catch((e) => {
            console.log(e);
        });

        console.log(attestationHex);

        await expect(await this.VerifyAddressAttestationTest.connect(sendingAddress).verify(attestationHex, attestorAddress)).to.not.throw;

        const tx = await this.VerifyAddressAttestationTest.verifyTest(attestationHex, attestorAddress);
        const txResult = await (tx.wait());

        console.log('txResult ==>', txResult.gasUsed);
        console.log('txResult1 ==>', txResult.cumulativeGasUsed.toString());
    });

    it("Java generated attestation should be valid", async function() {

        const issuerPubKeyPem = readFileSync(PREFIX_PATH + 'key-ec.txt', 'utf8');
        let issuerPubKey = KeyPair.publicFromBase64orPEM(issuerPubKeyPem);
        let attestorAddress = issuerPubKey.getAddress();

        const keyLinkingAttEcEcBase64 = readFileSync(PREFIX_PATH + 'signedEthereumKeyLinkingAttestation-mvp.txt', 'utf8');

        let keyLinkingAtt = new EthereumKeyLinkingAttestation();
        keyLinkingAtt.fromBase64(keyLinkingAttEcEcBase64);

        await expect(await this.VerifyAddressAttestationTest.verifyTest("0x" + uint8tohex(keyLinkingAtt.getEncoded()), attestorAddress)).to.not.throw;

    });


});
