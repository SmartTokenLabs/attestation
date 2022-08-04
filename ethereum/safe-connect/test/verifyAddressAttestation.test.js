const { expect } = require('chai');
const { ethers } = require('hardhat');

const { ATTESTOR_ADDRESS, SENDING_ADDRESS } = require("../scripts/constants");
const { createAttestation } = require('../scripts/utils');

describe("Verify Address Attestation", function () {
    before(async function () {
        let libFactory = await ethers.getContractFactory("LinkAttestUtils");
        let libObj = await libFactory.deploy();

        this.VerifyAddressAttestationTest = await ethers.getContractFactory('VerifyAddressAttestationTest', {
            libraries: {
                LinkAttestUtils: libObj.address,
            },
        });
        this.signers = await ethers.getSigners();
    });

    beforeEach(async function () {
        this.VerifyAddressAttestationTest = await (
          await this.VerifyAddressAttestationTest.deploy()
        ).deployed();
    });

    it("Attestation should be valid", async function () {
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

        await ethers.provider.send('evm_setNextBlockTimestamp', [Math.round(Date.now() / 1000) + 60]);
        await ethers.provider.send('evm_mine');

        await expect(await this.VerifyAddressAttestationTest.connect(sendingAddress).verify(attestationHex, attestorAddress)).to.not.throw;

        const tx = await this.VerifyAddressAttestationTest.verifyTest(attestationHex, attestorAddress);
        const txResult = await (tx.wait());

        console.log('txResult ==>', txResult.gasUsed);
        console.log('txResult1 ==>', txResult.cumulativeGasUsed.toString());
    });


});
