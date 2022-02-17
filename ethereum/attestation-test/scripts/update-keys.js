const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');

(async ()=>{
    const {
        rinkebyDeployKey
    } = await createWalletsAndAddresses(ethers.provider);

    const deployedRinkebyContract = '0xd2336c95896f8165D9e46Db4671d83ceA90C87F3';  //Deployed with rinkebyDeployKey
    const verificationContractAddress = '0x9328c7dEbFF674692136B3364c7D2dFa0D2dC2CA';
    const attestationKey = '';  //Insert here
    const issuerKey = '';       //Insert here

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

    const AttestationMintable = await ethers.getContractFactory("AttestationMintable");
    const mintableNFTTokens = await AttestationMintable.attach(deployedRinkebyContract);

    await mintableNFTTokens.connect(rinkebyDeployKey).updateAttestationKeys(attestationKey, issuerKey); //must use same key as contract deployment

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

})();
// npx hardhat run scripts/update-keys.js --network rinkeby
