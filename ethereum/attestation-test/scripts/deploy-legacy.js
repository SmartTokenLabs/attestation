const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');

(async ()=>{
    const {
        rinkebyDeployKey
    } = await createWalletsAndAddresses(ethers.provider);

    const debugAttestorKey = '0x538080305560986811c3c1A2c5BCb4F37670EF7e';  //Liscon attestor
    const debugIssuerKey = '0x4f3ceF0C905Eb4EDF9c4fFC71C4C4b06417BAC3E';    //Liscon Issuer
    const attestationKey = '';  //Insert here
    const issuerKey = '';       //Insert here

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

    //deploy Verification contract
    const VerifyAttestation = await ethers.getContractFactory("VerifyTicketLegacy");
    const verifyAttestation = await VerifyAttestation.deploy();
    await verifyAttestation.deployed();

    const AttestationMintable = await ethers.getContractFactory("AttestationMintable");
    const nftContract = await AttestationMintable.deploy(verifyAttestation.address, debugAttestorKey, debugIssuerKey);
    await nftContract.deployed();

    console.log("Verify Addr: " + verifyAttestation.address);
    console.log("NFT Addr: " + nftContract.address);
    console.log("Owner: " + rinkebyDeployKey.address);

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

})();
// npx hardhat run scripts/deploy-legacy.js --network rinkeby