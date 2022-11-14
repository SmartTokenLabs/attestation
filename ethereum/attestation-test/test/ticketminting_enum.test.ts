const { ethers, upgrades } = require('hardhat');

import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import {BigNumber, Contract} from "ethers";

describe("NFTMinter.Enumerable.deploy", function () {
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
    const ticketAttestation     = '0x308203603081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b3082024c308201f9a003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c58302e180f32303232303430383036313932305a0204624fd3e8180f32303332303430353036313933355a0204751bd6f7300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d04020342009d70ccb81a7747e38aeacc92f99e336bd93f98f246705c0bc668b45152c5aa6c39ba533ea730af3958b5026cfb7afc764ba3aa7aeac5b5b4f9509a80661e029f1b3068042007c1b13004ca0167ec16e390e8b8f1bde3582c2158430063172cf7651ee9345d044104243b4c5d5a18e2b5734953b98051bd8008d424ec043d55cbffea4b1681acfdab25d4027eb1571cd18d77cc468599c4564550643fdc3ef67231e530c2b2702d71040142';

    const expiredTktAttestation = '0x308203603081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b3082024c308201f9a003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c58302e180f32303232303430383036303133355a0204624fcfbf180f32303232303430383036303134365a0204624fcfca300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d04020342001ce2a2e4cfad8d3292fbe44f1bb378ab256594c25d6845ee212177396ca70e702278f592517c6d4ce326267e5b46abd730b70585917e03a6bdf8a9030ba5b1261b306804201c04c409902f0b457f6b0cfdc18d60b4b515b8fd807bdbee791c2e8300e24ffc044104004042988c655f600ad64e93a429ba537df8b36e7f82b04c18d5c396b7821895224afd704270a615ec3a1869d56cc74d16e5d54923411f844d4ff25d678c8ffa040142';
    // Fake: Identifier has a different issuer key
    const incorrectIssuerKey    = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c072260323034200c3c129bb60863add9b697779545ed7669a21fc585db7f6ef17b2591e1eb24a0816faefea7396beb4c30bb72acf81409c45d56c0605757aadb24293f7aaad86aa1c30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313132353233313632345a180f32303331313132333233313632345a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d0402034200a2a0fcd70a533448a14e9ae54965d5d9efeffaee8b7b7d97ebd4a51ccc467a181517eb5e86ecd61827c36f271961300394a686bea34e2dade751c9e21af2425a1c3068042017065ab2d131c89094c8467c0642d544c08b6d6aaa0554bdd77d3f09b5b3dadc0441040aee8b9f003f033117cdc02b702e08d0409c4e74d28c66c6175fb3c1a3036917205f8aea38b77e9cd3b69a870ddd8031cae8b0d275040476b69476229d85ba41040142';
    const incorrectAttestorKey  = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313132353233323133345a180f32303331313132333233323133345a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d040203420088c4fac11dbd4f287d7fa6e029fb9515268d67b550c80176fcb3e1f366eb5a87614ae253d535ee49160ed2944689fdbc82c97ba730560128eb60c0b590f2625c1b3068042017065ab2d131c89094c8467c0642d544c08b6d6aaa0554bdd77d3f09b5b3dadc0441040aee8b9f003f033117cdc02b702e08d0409c4e74d28c66c6175fb3c1a3036917205f8aea38b77e9cd3b69a870ddd8031cae8b0d275040476b69476229d85ba41040142';
    const incorrectPOK          = '0x308203543081a3305d0c04c385c3b8020f692a445689ca93d992fd24098b3dc60201000441042162047396b943e288498a9c2dc4a5621c62c792c33781fe34393b8955df9b230f8fd1ff3347f406d8545396018a22da0d23f7845e2ef299b075e1c07226032303420037ea340c4066047ecacfd21e323d5c2c2a710ff0e19a10c55bd49bebb0dad38255b7dde70487292202995a8d67ae57ef240d80fe280ce9d78596d450139828541b30820240308201eda003020112020101300906072a8648ce3d0402300e310c300a06035504030c03414c583022180f32303231313132363030323830315a180f32303331313132343030323830315a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414102010103420004950c7c0bed23c3cac5cc31bbb9aad9bb5532387882670ac2b1cdf0799ab0ebc764c267f704e8fdda0796ab8397a4d2101024d24c4efff695b3a417f2ed0e48cd300702012a02020539a35730553053060b2b060104018b3a737901280101ff04410415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4300906072a8648ce3d04020342003081c474f2d3cc9a94ab01c3adf8fd899f158017d9801fa7d5c77782528037265128d661f5061006b8fd0d3d57b59d679b687a2f166e8cc1989772d98a6edfd11c3068042007f1b13004ca0167ec16e390e8b8f1bde3582c2158430063172cf7651ee9345d044104243b4c5d5a18e2b5734953b98051bd8008d424ec043d55cbffea4b1681acfdab25d4027eb1571cd18d77cc468599c4564550643fdc3ef67231e530c2b2702d71040142';

    // Legacy format where commitment is NOT signed
    const lisconAttestation     = '0x3082035230819c30130c023236020a4c54374b5151335a575a0201010441042cbc8f988ce3c65426f26abdb3f756a6d87f0a04f9192d59dd4f72bfaa0a0d550fd0a2232ce0044a4fb8d7c18924ed2a34b784bc29b8ee6e927bf27064e4dbd003420016b7c24a62f8f85030af439cd049898a8b842d116d98d7946ea85e5d01da1af955aa5970ab0daa63c9445e27e2e684cf5b92ded50c9b1a3308d9970886c0fc8f1b30820246308201f3a00302011202083b1130036b0b5966300906072a8648ce3d040230163114301206035504030c0b416c70686157616c6c65743022180f32303231313231303036313633325a180f32303231313231303037313633325a300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101034200042f196ec33ad04c6398fe8eef1a84d8855397641bb4cbbbcf576e3baa34c516a51b2eac6b201dd24950b6513cbd85f6bd1a11b7bad511343d9dadeccb30f72642a35730553053060b2b060104018b3a737901280101ff04410401624a724c88c4f3f2410363708fb06cd1ec82613ae06019241d632f5143be722021d250d3e1240586d77be8aaa6b4df3a9327b44514d0179945cfd80222c237300906072a8648ce3d0402034200856b7cfb94bb42efa10a40fb00bad64a04d6cd0d64f9beb98af90046dba3a2520aeeef34a8423bc226875a4f2d9e2ad3e1e232f033b992f87a6067288a805f691b306704200a930ca0409547dd5712add6a3d6ef63c1b0ea5f8808666ea7f8aded54e5dbc504410414790e0e140ee15ea66fb01ef2d542506fbd5c55a0a0c67d85d92471f270f83625c997f48afefd04d83c2093efc580618f07985aceccdf36b987ba0e7d9ac3210400';

    // Legacy format where commitment is NOT signed
    const lisconAttestationV2Legacy   = "0x3082036230819c30130c023236020a4c54374b5151335a575a0201010441042cbc8f988ce3c65426f26abdb3f756a6d87f0a04f9192d59dd4f72bfaa0a0d550fd0a2232ce0044a4fb8d7c18924ed2a34b784bc29b8ee6e927bf27064e4dbd003420016b7c24a62f8f85030af439cd049898a8b842d116d98d7946ea85e5d01da1af955aa5970ab0daa63c9445e27e2e684cf5b92ded50c9b1a3308d9970886c0fc8f1b3082025630820203a0030201120208e7c377c674e5cdba300906072a8648ce3d040230163114301206035504030c0b416c70686157616c6c65743032180f32303232303430373031323131375a02060180019c86c8180f32303232303430373032323131375a0206018001d37548300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101034200042f196ec33ad04c6398fe8eef1a84d8855397641bb4cbbbcf576e3baa34c516a51b2eac6b201dd24950b6513cbd85f6bd1a11b7bad511343d9dadeccb30f72642a35730553053060b2b060104018b3a737901280101ff04410415d1e12efec966b999d9667e3fcf1e649ddfa4a322d7a43fcf49ed89aa780aa5022b013d9c596bd98076d21ddd8efedf944932248df15c7e37ea0836128876e0300906072a8648ce3d0402034200459bf7d6be948a95d98bab468a4198a672f61bd127e295899ef6eeea05a73c5c753cc8e56a1cb2c63106e4dd44b8038e07af2d112a99eaa3acdf58fbdf672bee1c306704202165f74f2eb907ca20fbec89105ebdd0dce7ca2cece0f1dd91e25273ef5704ca044104120913487762fa49c5afac6f59b4411e46d377d3a51444f8f5aedc837f8f681e0898e3b35ecd515cf7c1438c66210daf1167b388a52e9ef3b318b2a56307c9070400";
    const ticketAttestationId = BigNumber.from('0x692a445689ca93d992fd24098b3dc6');
    const lisconTicketId = BigNumber.from('0x4c54374b5151335a575a');

    // real life attestation
    const att2     = '0x3082036130819f30590c0e4174746573746174696f6e44414f0201040201000441041879356d9b56e4bd56313db34203629c97a22f6377b54f81a469db3c5cc6c46d24500ded69e170d4014bcb5175507ffaf601e61c162fe4f2a414e9a0eef1c9800342000ccc8835b2aff4c5f6dad57c3b3abda847ab0885438d53598b33b30a0049410367b00dd3cf8297eaf2f178c4da0fb509801d6f22f0ba5be9bc8dcec18256e94c1b30820252308201ffa0030201120208b87e97897399e8bd300906072a8648ce3d040230163114301206035504030c0b416c70686157616c6c6574302e180f32303232303530343230333935385a02046272e49e180f32303232303530343231333935385a02046272f2ae300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101034200042f196ec33ad04c6398fe8eef1a84d8855397641bb4cbbbcf576e3baa34c516a51b2eac6b201dd24950b6513cbd85f6bd1a11b7bad511343d9dadeccb30f72642a35730553053060b2b060104018b3a737901280101ff0441041246a015d46185b629dadb77a3ff8f43be7e6374e7c40529f018b8b98d89893b0e568a4e4950d90c8ebfc28a27764d23a398f39ff1c25e94ace6423b3b9c6ccb300906072a8648ce3d040203420016301181d5a938737480b7fd4f17785a179912f7879d343572771c2e2cbbfb1c7af5ffbf00dc348120ee1d217d7c147d5933fc3674235f51593373b408a0031b1c306704200a5caa05cd01c8156826e26e98b65a1924c66651ec3603257a384382d0caf2710441040a86c5a47d176f1c4fcae36e6f1a612cb3f21f8d647eb2a1203a43e66ab267342594ddf72f16e773b5d1bfda0ba7ac1b32cbd5fbd2f673b1989b004966ba6e5c0400';

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

        const VerifyAttestation = await ethers.getContractFactory("VerifyTicket");
        verifyAttestation = await VerifyAttestation.deploy();
        await verifyAttestation.deployed();

        const LegacyAttestation = await ethers.getContractFactory("VerifyTicketLegacy");
        lisconVerification = await LegacyAttestation.deploy();
        await lisconVerification.deployed();


        const AttestationMintable = await ethers.getContractFactory("AttestationMintableEnumerable");
        nftContract = await AttestationMintable.deploy(attestorKeyAddress, issuerKeyAddress);
        await nftContract.deployed();

        lisconNFT = await AttestationMintable.deploy(lisconAttestor, lisconIssuer);
        await lisconNFT.deployed();

        console.log("Verify Addr: " + verifyAttestation.address);
        console.log("NFT Addr: " + nftContract.address);
        console.log("Liscon Verify Addr: " + lisconVerification.address);
        console.log("Owner: " + owner.address);

    })

    it("Validate Attestation v2", async function(){

        await expect(verifyAttestation["verifyTicketAttestation(bytes)"](att2)).to.not.throw;

        // if it doesnt throw then all good
        // expect(1).to.be.eq(1); 
    });

    // Note: this test was created before we checked the timestamp
    // It appears that it should fail now we handle timestamps
    it("Validate Legacy Liscon Attestation v2", async function(){

        let result1 = await verifyAttestation["verifyTicketAttestation(bytes)"](att2);
        console.log(result1);

        let result = await lisconVerification["verifyTicketAttestation(bytes)"](lisconAttestationV2Legacy);

        //console.log("Attestor: " + result.attestor);
        //console.log("ticketIssuer: " + result.ticketIssuer);
        //console.log("subject: " + result.subject);
        //console.log("ticketId: " + result.ticketId);
        //console.log("isValid: " + result.attestationValid);
        expect(result.ticketId).to.be.eq('0x'); // Because if timestamp fails, we blank the attestation return
        expect(result.attestationValid).to.be.eq(false); // Timestamp fails

        // disable this tests, because it will fail in 1 hour
        //expect(result.attestor).to.be.eq('0x538080305560986811c3c1A2c5BCb4F37670EF7e');
        //expect(result.ticketIssuer).to.be.eq('0x4f3ceF0C905Eb4EDF9c4fFC71C4C4b06417BAC3E');
        // expect(result.subject).to.be.eq('0x2F21dC12dd43bd15b86643332041ab97010357D7');
    })

    it("Mint NFT from Attestation", async function(){
        {
            var startingBalance = await nftContract.balanceOf(subjectAddress);
            console.log("Starting balance for Subject: " + startingBalance);

            //check expired attestation
            await expect( nftContract.mintUsingAttestation(expiredTktAttestation)).to.be.revertedWith('Attestation not valid');

            //first attempt to mint from expired attestation
            let txReceipt = await nftContract.mintUsingAttestation(ticketAttestation);
            let minted = await txReceipt.wait();

            let transferEvent = minted.events?.filter((x:any) => {return x.event == "Transfer"});
            console.log("Mint TokenID: ");
            let args = transferEvent[0].args;
            var tokenIdBN : BigNumber;
            if (args){
                console.log(`Token ID: ${args.tokenId.toHexString()}`);
                tokenIdBN = BigNumber.from(args.tokenId);
            }
            else {
                tokenIdBN = BigNumber.from(0);
            }

            console.log("TokenID: " + tokenIdBN);

            expect( tokenIdBN ).to.be.equal(ticketAttestationId);

            var newBalance = await nftContract.balanceOf(subjectAddress);

            console.log("New Balance for Subject after minting: " + newBalance);

            expect(newBalance).to.be.equal(1);

            //try minting again, should fail
            await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('ERC721: token already minted');

            newBalance = await nftContract.balanceOf(subjectAddress);

            console.log("New Balance for Subject after minting a second time: " + newBalance);
            expect(newBalance).to.be.equal(1);
        }
    });

    it("Mint Liscon NFT from Attestation", async function(){
            {
//                 var startingBalance = await lisconNFT.balanceOf(lisconSubject);
//                 console.log("Starting balance for Subject: " + startingBalance);
//
//                 let txReceipt = await lisconNFT.mintUsingAttestation(lisconAttestation);
//                 let minted = await txReceipt.wait();
//                 // console.log(minted.events[0].args);
//
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
//                 await expect( lisconNFT.mintUsingAttestation(lisconAttestation)).to.be.revertedWith('ERC721: token already minted');
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
            // try URL
            var expectedUrl = "https://alchemynft.io/31337/" + ethers.utils.getAddress(nftContract.address) + "/" + ticketAttestationId + ".json";
            var tokenUrl = await nftContract.tokenURI(ticketAttestationId);
            console.log("Token URL: " + tokenUrl);
            expect(tokenUrl.toLowerCase()).to.be.equal(expectedUrl.toLowerCase());

            //try updating the attestor and issuer keys
            await nftContract.updateAttestationKeys(randomAddress, randomUserAddress);

            //validation should fail
            await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('Attestation not valid');

            //change keys back, should get 'already minted'
            await nftContract.updateAttestationKeys(attestorKeyAddress, issuerKeyAddress);

            //validation should fail
            await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('ERC721: token already minted');

            //change validation contract to random address JB: no longer done
            //await nftContract.updateVericationAddress(randomAddress);

            //Should fail: JB: Will not fail because now verification system is part of the contract
            //await expect( nftContract.mintUsingAttestation(ticketAttestation)).to.be.revertedWith('Transaction reverted: function call to a non-contract account');

            //attempt to use these functions with a different key (non owner)
            await expect( nftContract.connect(addr1).updateAttestationKeys(randomAddress, randomUserAddress)).to.be.revertedWith('Ownable: caller is not the owner');
            //await expect( nftContract.connect(addr1).updateVericationAddress(randomAddress)).to.be.revertedWith('Ownable: caller is not the owner'); // JB: No longer can change this
        }
    });

    let nftContractMintedTokenID = "546048445646851568430134455064804806";

    it("Test Enumerable", async function(){
        expect(await nftContract.supportsInterface("0x780e9d63")).to.eq(true);
        expect(await nftContract.balanceOf(subjectAddress)).to.eq(1);
        expect(await nftContract.totalSupply()).to.eq(1);
        expect((await nftContract.tokenOfOwnerByIndex(subjectAddress,0)).toString()).to.eq(nftContractMintedTokenID);
        expect((await nftContract.tokenByIndex(0)).toString()).to.eq(nftContractMintedTokenID);
        // console.log(await nftContract.tokenByIndex(1));
    })

    it("Test Ownable", async function(){
        await expect(nftContract.connect(addr1).transferOwnership(subjectAddress)).to.be.revertedWith("Ownable: caller is not the owner");
        expect(await nftContract.transferOwnership(addr1.address)).to.emit(nftContract, "OwnershipTransferred");

    })

});
