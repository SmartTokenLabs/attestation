const { expect } = require('chai');
const { ethers } = require('hardhat');

const {createAttestation} = require("../scripts/utils");

describe("Mint using NFT attestation", function () {

    before(async function () {

        await hre.network.provider.send("hardhat_reset");
        await ethers.provider.send('evm_setNextBlockTimestamp', [Math.round(Date.now() / 1000)]);

        const [owner, addr1, addr2] = await ethers.getSigners();

        this.STLBayc = await ethers.getContractFactory('STLBayc');
        this.stlBayc = await (
            await this.STLBayc.deploy()
        ).deployed();

        console.log("Bayc contract constructed");

        await this.stlBayc.connect(addr1).safeMint(addr1.address, "https://gateway.pinata.cloud/ipfs/QmXdnWNa2CaRCUa4jMTirmkVJkygr2LtnccSuDY3yXrvVm/bayc_1013.json");

        console.log("Bayc tokens minted");

        let libFactory = await ethers.getContractFactory("LinkAttestUtils");
        let libObj = await libFactory.deploy();

        this.STLTNMint = await ethers.getContractFactory('STLTNMintNFTAttest', {
            libraries: {
                LinkAttestUtils: libObj.address,
            },
        });
        this.stlTnMint = await (
            await this.STLTNMint.deploy(this.stlBayc.address)
        ).deployed();

        this.nftOwner = addr1;
        this.linkedAddress = addr2;

    });

    beforeEach(async function () {

    });

    it("Mint with attestation", async function () {

        let attestationHex = await createAttestation({ contract: this.stlBayc.address, chain: "4"}, this.linkedAddress.address);

        let amount = 1000n * 1000000000000000000n;

        await expect(await this.stlTnMint.connect(this.linkedAddress).mint(attestationHex, this.linkedAddress.address, amount)).to.not.throw;
    });

});