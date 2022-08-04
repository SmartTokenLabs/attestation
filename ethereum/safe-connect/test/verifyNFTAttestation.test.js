const { expect } = require('chai');
const { ethers } = require('hardhat');

const { ATTESTOR_ADDRESS, SENDING_ADDRESS } = require("../scripts/constants");
const { createAttestation } = require('../scripts/utils');

describe("Verify NFT Attestation", function () {

    before(async function () {
        let libFactory = await ethers.getContractFactory("LinkAttestUtils");
        let libObj = await libFactory.deploy();

        libFactory = await ethers.getContractFactory("VerifyNFTAttestation", {
            libraries: {
                LinkAttestUtils: libObj.address,
            }
        });
        let libObj2 = await libFactory.deploy();

        this.VerifyNFTAttestationTest = await ethers.getContractFactory('VerifyNFTAttestationTest', {
            libraries: {
                LinkAttestUtils: libObj.address,
                VerifyNFTAttestation: libObj2.address
            },
        });

        this.VerifyNFTAttestationTest = await (
            await this.VerifyNFTAttestationTest.deploy()
        ).deployed();

        this.signers = await ethers.getSigners();
    });

    let tokenAsn = "301c04143d8a0fb32b0f586fdc10447c22f477979dc526ec040101020104";

    it("Token length decode", async function () {

        let num = await this.VerifyNFTAttestationTest.numberOfTokens("0x" + tokenAsn);

        await expect(num).to.equal(1);

        num = await this.VerifyNFTAttestationTest.numberOfTokens("0x" + tokenAsn + tokenAsn);

        await expect(num).to.equal(2);

        num = await this.VerifyNFTAttestationTest.numberOfTokens("0x" + tokenAsn + tokenAsn + tokenAsn);

        await expect(num).to.equal(3);
    });

    it("Token data decode", async function () {

        let tokens = await this.VerifyNFTAttestationTest.decodeTokens("0x" + tokenAsn + tokenAsn + tokenAsn);

        for (let token of tokens){
            await expect(token.addr).to.equal("0x3d8a0fB32b0F586FdC10447c22F477979dc526ec");
            await expect(token.tokenId).to.equal(1);
            await expect(token.chainId).to.equal(4);
        }

    });

    it("Attestation should be valid", async function () {
        let attestorAddress = ATTESTOR_ADDRESS;

        let sendingAddress = SENDING_ADDRESS;

        console.log("create attestation");

        let attestationHex = await createAttestation(
            { contract: "0x3d8a0fB32b0F586FdC10447c22F477979dc526ec", chain: "4"}, // NFT owner wallet
            sendingAddress // linked address
        ).catch((e) => {
            console.log(e);
        });

        console.log(attestationHex);

        await ethers.provider.send('evm_setNextBlockTimestamp', [Math.round(Date.now() / 1000) + 60]);
        await ethers.provider.send('evm_mine');

        await expect(await this.VerifyNFTAttestationTest.connect(sendingAddress).verify(attestationHex, attestorAddress)).to.not.throw;

        const tx = await this.VerifyNFTAttestationTest.verifyTest(attestationHex, attestorAddress);
        const txResult = await (tx.wait());

        console.log('txResult ==>', txResult.gasUsed);
        console.log('txResult1 ==>', txResult.cumulativeGasUsed.toString());
    });


});
