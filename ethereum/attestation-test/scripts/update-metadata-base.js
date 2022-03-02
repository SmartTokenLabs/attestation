const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');

(async ()=>{
    const {
        rinkebyDeployKey
    } = await createWalletsAndAddresses(ethers.provider);

    const deployedRinkebyContract = '0xd2336c95896f8165D9e46Db4671d83ceA90C87F3';  //Deployed with rinkebyDeployKey
    const newMetadataBase = 'https://ipfs.io/ipfs/QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/'; 

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

    const AttestationMintable = await ethers.getContractFactory("AttestationMintable");
    const mintableNFTTokens = await AttestationMintable.attach(deployedRinkebyContract);

    await mintableNFTTokens.connect(rinkebyDeployKey).updateBaseURL(newMetadataBase); //must use same key as contract deployment

    //TODO: Add known token to test new URL
    //const token1Url = await mintableNFTTokens.tokenURI(1);
    //console.log("Check updated baseUrl: " + token1Url);

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

})();
// npx hardhat run scripts/update-keys.js --network rinkeby
