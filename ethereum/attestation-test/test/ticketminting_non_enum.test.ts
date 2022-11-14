const { ethers, upgrades } = require('hardhat');

import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import {BigNumber, Contract} from "ethers";

describe("NFTMinter.deploy", function () {
    let verifyAttestation: Contract;
    let nftContract: Contract;

    let lisconVerification: Contract;
    let lisconNFT: Contract;

    let owner: SignerWithAddress;
    let addr1: SignerWithAddress;
    let addr2: SignerWithAddress;

    let randomAddress = "0x538080305560986811c3c1A2c5BCb4F37670EF7e";
    let randomUserAddress = "0x0C770da98559DD6806a6C7cbC77411cF7a9042Ae";

    const attestorKeyAddress = '0x5f7bFe752Ac1a45F67497d9dCDD9BbDA50A83955';
    const issuerKeyAddress = '0xbf9Ae773d7D724b9632564fbE2c782Cc2Ed8817c';
    const subjectAddress = '0x7a181cb7250776E16783f9d3c9166de0f95AB283';

    const lisconAttestor = '0x538080305560986811c3c1A2c5BCb4F37670EF7e';
    const lisconIssuer = '0x4f3ceF0C905Eb4EDF9c4fFC71C4C4b06417BAC3E';
    const lisconSubject = '0x2F21dC12dd43bd15b86643332041ab97010357D7';

    const ganacheChainId = 31337;

    // 5 tokens attestation
    // Current devcon ticket format where commitment is signed
    const ticketAttestation     = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313131373036303533375a180f32303331313131353036303533375a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d0402034200214b1a115619715ba871ff82bb545857e8dc9e72237490c6021461cebe67fd7249c8cb660a97f75ac9aa145f38f0acbc4f282fbc0492931d1fa0e2fd5cca12931c3068042007c1b13004ca0167ec16e390e8b8f1bde3582c2158430063172cf7651ee9345d044104243b4c5d5a18e2b5734953b98051bd8008d424ec043d55cbffea4b1681acfdab25d4027eb1571cd18d77cc468599c4564550643fdc3ef67231e530c2b2702d71040142';
    // Fake: Identifier has a different issuer key
    const incorrectIssuerKey    = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c072260323034200c3c129bb60863add9b697779545ed7669a21fc585db7f6ef17b2591e1eb24a0816faefea7396beb4c30bb72acf81409c45d56c0605757aadb24293f7aaad86aa1c30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313132353233313632345a180f32303331313132333233313632345a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d0402034200a2a0fcd70a533448a14e9ae54965d5d9efeffaee8b7b7d97ebd4a51ccc467a181517eb5e86ecd61827c36f271961300394a686bea34e2dade751c9e21af2425a1c3068042017065ab2d131c89094c8467c0642d544c08b6d6aaa0554bdd77d3f09b5b3dadc0441040aee8b9f003f033117cdc02b702e08d0409c4e74d28c66c6175fb3c1a3036917205f8aea38b77e9cd3b69a870ddd8031cae8b0d275040476b69476229d85ba41040142';
    const incorrectAttestorKey  = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313132353233323133345a180f32303331313132333233323133345a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d040203420088c4fac11dbd4f287d7fa6e029fb9515268d67b550c80176fcb3e1f366eb5a87614ae253d535ee49160ed2944689fdbc82c97ba730560128eb60c0b590f2625c1b3068042017065ab2d131c89094c8467c0642d544c08b6d6aaa0554bdd77d3f09b5b3dadc0441040aee8b9f003f033117cdc02b702e08d0409c4e74d28c66c6175fb3c1a3036917205f8aea38b77e9cd3b69a870ddd8031cae8b0d275040476b69476229d85ba41040142';
    const incorrectPOK          = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313132363030323830315a180f32303331313132343030323830315a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d04020342003081c474f2d3cc9a94ab01c3adf8fd899f158017d9801fa7d5c77782528037265128d661f5061006b8fd0d3d57b59d679b687a2f166e8cc1989772d98a6edfd11c3068042007f1b13004ca0167ec16e390e8b8f1bde3582c2158430063172cf7651ee9345d044104243b4c5d5a18e2b5734953b98051bd8008d424ec043d55cbffea4b1681acfdab25d4027eb1571cd18d77cc468599c4564550643fdc3ef67231e530c2b2702d71040142';

    // Legacy format where commitment is NOT signed
    const lisconAttestation     = '0x3082035230819c30130c023236020a4c54374b5151335a575a0201010441042cbc8f988ce3c65426f26abdb3f756a6d87f0a04f9192d59dd4f72bfaa0a0d550fd0a2232ce0044a4fb8d7c18924ed2a34b784bc29b8ee6e927bf27064e4dbd003420016b7c24a62f8f85030af439cd049898a8b842d116d98d7946ea85e5d01da1af955aa5970ab0daa63c9445e27e2e684cf5b92ded50c9b1a3308d9970886c0fc8f1b30820246308201f3a00302011202083b1130036b0b5966300906072a8648ce3d040230163114301206035504030c0b416c70686157616c6c65743022180f32303231313231303036313633325a180f32303231313231303037313633325a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101034200042f196ec33ad04c6398fe8eef1a84d8855397641bb4cbbbcf576e3baa34c516a51b2eac6b201dd24950b6513cbd85f6bd1a11b7bad511343d9dadeccb30f72642a35730553053060b2b060104018b3a737901280101ff04410401624a724c88c4f3f2410363708fb06cd1ec82613ae06019241d632f5143be722021d250d3e1240586d77be8aaa6b4df3a9327b44514d0179945cfd80222c237300906072a8648ce3d0402034200856b7cfb94bb42efa10a40fb00bad64a04d6cd0d64f9beb98af90046dba3a2520aeeef34a8423bc226875a4f2d9e2ad3e1e232f033b992f87a6067288a805f691b306704200a930ca0409547dd5712add6a3d6ef63c1b0ea5f8808666ea7f8aded54e5dbc504410414790e0e140ee15ea66fb01ef2d542506fbd5c55a0a0c67d85d92471f270f83625c997f48afefd04d83c2093efc580618f07985aceccdf36b987ba0e7d9ac3210400';

    const ticketAttestationId = BigNumber.from('0x692a445689ca93d992fd24098b3dc6');
    const lisconTicketId = BigNumber.from('0x4c54374b5151335a575a');

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


        const AttestationMintable = await ethers.getContractFactory("AttestationMintable");
        nftContract = await AttestationMintable.deploy(attestorKeyAddress, issuerKeyAddress);
        await nftContract.deployed();

        lisconNFT = await AttestationMintable.deploy(lisconAttestor, lisconIssuer);
        await lisconNFT.deployed();

        console.log("NFT Addr: " + nftContract.address);
        //console.log("Liscon Verify Addr: " + lisconVerification.address);
        console.log("Owner: " + owner.address);

    })

    it("Mint NFT from Attestation", async function(){
        {
//             var startingBalance = await nftContract.balanceOf(subjectAddress);
//             console.log("Starting balance for Subject: " + startingBalance);
//
//             let txReceipt = await nftContract.mintUsingAttestation(ticketAttestation);
//             let minted = await txReceipt.wait();
//
//             let transferEvent = minted.events?.filter((x:any) => {return x.event == "Transfer"});
//             console.log("Mint TokenID: ");
//             let args = transferEvent[0].args;
//             var tokenIdBN : BigNumber;
//             if (args){
//                 console.log(`Token ID: ${args.tokenId.toHexString()}`);
//                 tokenIdBN = BigNumber.from(args.tokenId);
//             }
//             else {
//                 tokenIdBN = BigNumber.from(0);
//             }
//
//             console.log("TokenID: " + tokenIdBN);
//
//             expect( tokenIdBN ).to.be.equal(ticketAttestationId);
//
//             var newBalance = await nftContract.balanceOf(subjectAddress);
//
//             console.log("New Balance for Subject after minting: " + newBalance);
//
//             expect(newBalance).to.be.equal(1);
//
//             //try minting again, should fail
//             await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('AttestationMintable: token already minted');
//
//             newBalance = await nftContract.balanceOf(subjectAddress);
//
//             console.log("New Balance for Subject after minting a second time: " + newBalance);
//             expect(newBalance).to.be.equal(1);
        }
    });

    it("Mint Liscon NFT from Attestation", async function(){
            {
//                 var startingBalance = await lisconNFT.balanceOf(lisconSubject);
//                 console.log("Starting balance for Subject: " + startingBalance);
//
//                 let txReceipt = await lisconNFT.mintUsingAttestation(lisconAttestation);
//                 let minted = await txReceipt.wait();
//
//                 let transferEvent = minted.events?.filter((x:any) => {return x.event == "Transfer"});
//                 console.log("Mint TokenID: ");
//                 let args = transferEvent[0].args;
//                 var tokenIdBN : BigNumber;
//                 if (args){
//                     console.log(`Token ID: ${args.tokenId.toHexString()}`);
//                     tokenIdBN = BigNumber.from(args.tokenId);
//                 }
//                 else {
//                     tokenIdBN = BigNumber.from(0);
//                 }
//
//                 console.log("TokenID: " + tokenIdBN);
//
//                 expect( tokenIdBN ).to.be.equal(lisconTicketId);
//
//                 var newBalance = await lisconNFT.balanceOf(lisconSubject);
//
//                 console.log("New Balance for Subject after minting: " + newBalance);
//
//                 expect(newBalance).to.be.equal(1);
//
//                 //try minting again, should fail
//                 await expect( lisconNFT.mintUsingAttestation(lisconAttestation)).to.be.revertedWith('AttestationMintable: token already minted');
//
//                 newBalance = await lisconNFT.balanceOf(lisconSubject);
//
//                 console.log("New Balance for Subject after minting a second time: " + newBalance);
//                 expect(newBalance).to.be.equal(1);


            }
        });

    it("Try negative tests", async function(){
        {
            // attempt to claim an attestation which is built with a signature from a different ticketIssuer
            var startingBalance = await nftContract.balanceOf(subjectAddress); 
            console.log("Starting balance for Subject: " + startingBalance);
            await expect( nftContract.mintUsingAttestation(incorrectIssuerKey)).to.be.revertedWith('Attestation not valid');

            // attempt to claim an attestation which is built with a signature from a different identity attestor
            await expect( nftContract.mintUsingAttestation(incorrectAttestorKey)).to.be.revertedWith('Attestation not valid');

            // Now with an incorrect ZKP 
            await expect( nftContract.mintUsingAttestation(incorrectPOK)).to.be.revertedWith('Attestation not valid');
        }
    });

    it("Test Contract functions", async function(){
        {
//             // try URL
//             var expectedUrl = "https://alchemynft.io/31337/" + ethers.utils.getAddress(nftContract.address) + "/" + ticketAttestationId + ".json";
//             var tokenUrl = await nftContract.tokenURI(ticketAttestationId);
//             console.log("Token URL: " + tokenUrl);
//             expect(tokenUrl.toLowerCase()).to.be.equal(expectedUrl.toLowerCase());
//
//             //try updating the attestor and issuer keys
//             await nftContract.updateAttestationKeys(randomAddress, randomUserAddress);
//
//             //validation should fail
//             await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('Attestation not valid');
//
//             //change keys back, should get 'already minted'
//             await nftContract.updateAttestationKeys(attestorKeyAddress, issuerKeyAddress);
//
//             //validation should fail
//             await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('AttestationMintable: token already minted');
//
//             //change validation contract to random address
//             await nftContract.updateVericationAddress(randomAddress);
//
//             //Should fail
//             await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('Transaction reverted: function call to a non-contract account');
//
//             //attempt to use these functions with a different key (non owner)
//             await expect( nftContract.connect(addr1).updateAttestationKeys(randomAddress, randomUserAddress)).to.be.revertedWith('AttestationMintable: caller is not the owner');
//             await expect( nftContract.connect(addr1).updateVericationAddress(randomAddress)).to.be.revertedWith('AttestationMintable: caller is not the owner');
        }
    });

});
