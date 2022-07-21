const { expect } = require('chai');
const { ethers } = require('hardhat');

const {createAttestation} = require("../scripts/utils");

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

        let attestationHex = await createAttestation(this.nftOwner.address, this.linkedAddress.address);

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