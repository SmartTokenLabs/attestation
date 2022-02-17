const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');

(async ()=>{
    const {
        rinkebyDeployKey2
    } = await createWalletsAndAddresses(ethers.provider);

    const debugAttestorKey = '0x538080305560986811c3c1A2c5BCb4F37670EF7e';  //Liscon attestor
    const debugIssuerKey = '0x4f3ceF0C905Eb4EDF9c4fFC71C4C4b06417BAC3E';    //Liscon Issuer
    let verifyContract;
    const attestationKey = '';  //Insert here
    const issuerKey = '';       //Insert here

    const { chainId } = await ethers.provider.getNetwork();

    switch (chainId) {
        case 4: // Ethereum Testnet Rinkeby
        verifyContract = "0xc7823eaa8f87E8B8DF09364F52045abc504473a6";
            break;
        case 421611: //Arbitrum Testnet Rinkeby
        verifyContract = "0xb00cDC8392640b2b1F5A069d10A7BDCFd7c618FA";
            break;
        case 69: // Optimistic Ethereum Testnet Kovan
        verifyContract = "0xb00cDC8392640b2b1F5A069d10A7BDCFd7c618FA";
            break;
        case 80001: // Polygon Testnet Mumbai
        verifyContract = "0x2E37dAA5A76aA2D6B92d87D57fa0D41d3513A8E3";
            break;
        default: throw new Error("Unknown network to upgrade to Enum.");
    }

    if (chainId == 31337 || chainId == 1337) { //default HH ganache Id for testing, provide balances
        await owner.sendTransaction({
            to: rinkebyDeployKey2.address,
            value: ethers.utils.parseEther("3.0")
        });

    }

    // "name": "Ethereum Testnet Rinkeby",
    // "verify": "0xc7823eaa8f87E8B8DF09364F52045abc504473a6", // Liscon legacy ticket
    // "liscon": "0x8Ce63eCBc7c69A37Ae4Fe609Aacd8c4A3e5613bC",

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey2.address)), "\n");


    const AttestationMintable = await ethers.getContractFactory("AttestationMintableEnumerable");
    const nftContract = await AttestationMintable.connect(rinkebyDeployKey2).deploy(verifyContract, debugAttestorKey, debugIssuerKey);
    await nftContract.deployed();

    console.log("Verify Addr: " + verifyContract);
    console.log("NFT Enum Addr: " + nftContract.address);
    console.log("Owner: " + rinkebyDeployKey2.address);

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey2.address)), "\n");

})();
// npx hardhat run scripts/deploy-legacy.js --network rinkeby