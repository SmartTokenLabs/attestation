const { ethers, upgrades } = require('hardhat');

import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import {BigNumber, Contract} from "ethers";
import exp from "constants";

describe("NFTMinter.deploy", function () {
    let verifyAttestation: Contract;
    let nftContract: Contract;

    let owner: SignerWithAddress;
    let addr1: SignerWithAddress;
    let addr2: SignerWithAddress;
    let testAddr: SignerWithAddress;
    let testAddr2: SignerWithAddress;
    let deployAddr: SignerWithAddress;

    let randomAddress = "0x538080305560986811c3c1A2c5BCb4F37670EF7e";
    let randomUserAddress = "0x0C770da98559DD6806a6C7cbC77411cF7a9042Ae";

    const attestorKeyAddress = '0x5f7bFe752Ac1a45F67497d9dCDD9BbDA50A83955';
    const issuerKeyAddress = '0xbf9Ae773d7D724b9632564fbE2c782Cc2Ed8817c';
    const subjectAddress = '0x7a181cb7250776E16783f9d3c9166de0f95AB283';

    const ganacheChainId = 31337;

    // 5 tokens attestation
    const ticketAttestation     = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313131373036303533375a180f32303331313131353036303533375a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d0402034200214b1a115619715ba871ff82bb545857e8dc9e72237490c6021461cebe67fd7249c8cb660a97f75ac9aa145f38f0acbc4f282fbc0492931d1fa0e2fd5cca12931c3068042007c1b13004ca0167ec16e390e8b8f1bde3582c2158430063172cf7651ee9345d044104243b4c5d5a18e2b5734953b98051bd8008d424ec043d55cbffea4b1681acfdab25d4027eb1571cd18d77cc468599c4564550643fdc3ef67231e530c2b2702d71040142';
    // Fake: Identifier has a different attestor
    const fakeTicketAttestation = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313131373036303533375a180f32303331313131353036303533375a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d0402034200214b1a115619715ba871ff82bb545857e8dc9e72237490c6021461cebe67fd7249c8cb660a97f75ac9aa145f38f0acbc4f282fbc0492931d1fa0e2fd5cca12931c3068042007c1b13004ca0167ec16e390e8b8f1bde3582c2158430063172cf7651ee9345d044104243b4c5d5a18e2b5734953b98051bd8008d424ec043d55cbffea4b1681acfdab25d4027eb1571cd18d77cc468599c4564550643fdc3ef67231e530c2b2702d71040142';
    const attestationSubjectPrivateKey = '0x3C19FF5D453C7891EDB92FE70662D5E45AEF658E9F38DF9B0483F6AE2D8DE66E';
    const anyPrivateKey = '0x2222222222222222222222222222222222222222222222222222222222222222';
    const anyPrivateKey2 = '0x2222222222222222222222222222222222222222222222222222222222222666';

    function calcContractAddress(sender: SignerWithAddress, nonce: number)
    {
        const rlp = require('rlp');
        const keccak = require('keccak');

        var input_arr = [ sender.address, nonce ];
        var rlp_encoded = rlp.encode(input_arr);

        var contract_address_long = keccak('keccak256').update(rlp_encoded).digest('hex');

        var contract_address = contract_address_long.substring(24); //Trim the first 24 characters.
        return "0x" + contract_address;
    }

    it("deploy contracts", async function(){
        [owner, addr1, addr2] = await ethers.getSigners();

        testAddr = new ethers.Wallet(anyPrivateKey, owner.provider);
        testAddr2 = new ethers.Wallet(attestationSubjectPrivateKey, owner.provider);
        deployAddr = new ethers.Wallet(anyPrivateKey2, owner.provider);

        const VerifyAttestation = await ethers.getContractFactory("VerifyTicket");
        verifyAttestation = await VerifyAttestation.deploy();
        await verifyAttestation.deployed();

        await addr1.sendTransaction({
            to: deployAddr.address,
            value: ethers.utils.parseEther("1.0")
        });

        const AttestationMintable = await ethers.getContractFactory("AttestationMintable");
        nftContract = await AttestationMintable.deploy(verifyAttestation.address, attestorKeyAddress, issuerKeyAddress);
        await nftContract.deployed();

        console.log("Verify Addr: " + verifyAttestation.address);
        console.log("NFT Addr: " + nftContract.address);
        console.log("Owner: " + owner.address);

    })

    it("Mint NFT from Attestation", async function(){
        {
            var startingBalance = await nftContract.balanceOf(subjectAddress); 
            console.log("Starting balance for Subject: " + startingBalance);

            let txReceipt = await nftContract.mintUsingAttestation(ticketAttestation);

            console.log("RCP: " + txReceipt);

            
            // console.log(events);

            let transferEvent = txReceipt.events?.filter((x:any) => {return x.event == "Transfer"});
            //console.log("Mint TokenID: " + transferEvent[0].args.tokenId);
            console.log("Mint TokenID: " + transferEvent);
            let eventFilter = await nftContract.filters.Transfer();
            let events = await nftContract.queryFilter(eventFilter);
            let eventArgs = events[0].args;
            console.log(eventArgs);
            console.log(events[0]);

            //How to get the event.tokenId ??



            var newBalance = await nftContract.balanceOf(subjectAddress); 

            console.log("New Balance for Subject after minting: " + newBalance);

            //try minting again, should fail
            await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('ERC721: token already minted');

            newBalance = await nftContract.balanceOf(subjectAddress); 

            console.log("New Balance for Subject after minting a second time: " + newBalance);            
        }
    });

    it("Try negative test", async function(){
        // create a tip transaction and try to claim it
        {
            
        }
    });

});
