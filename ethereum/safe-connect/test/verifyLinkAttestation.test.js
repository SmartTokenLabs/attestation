const { expect } = require('chai');
const { ethers } = require('hardhat');

const { ATTESTOR_ADDRESS, SENDING_ADDRESS } = require("../scripts/constants");
const { createAttestation } = require('../scripts/utils');

describe("Verify Link Attestation", function () {
    before(async function () {
        this.VerifyLinkAttestationTest = await ethers.getContractFactory('VerifyLinkAttestationTest');
        this.signers = await ethers.getSigners();
    });

    beforeEach(async function () {
        this.verifyLinkAttestationTest = await (
          await this.VerifyLinkAttestationTest.deploy()
        ).deployed();
    });

    it("Attestation should be valid", async function () {
        let attestorAddress = ATTESTOR_ADDRESS;

        let sendingAddress = SENDING_ADDRESS;

        let attestationHex = await createAttestation(
            this.signers[0].address, // NFT owner wallet
            sendingAddress // linked address
        );

        await expect(await this.verifyLinkAttestationTest.connect(sendingAddress).verifyAddressAttestation(attestationHex, attestorAddress)).to.not.throw;

        const tx = await this.verifyLinkAttestationTest.verifyAddressAttestationTest(attestationHex, attestorAddress);
        const txResult = await (tx.wait());

        console.log('txResult ==>', txResult.gasUsed);
        console.log('txResult1 ==>', txResult.cumulativeGasUsed.toString());
    });


});
