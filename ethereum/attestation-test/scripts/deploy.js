const { ethers } = require("hardhat");
const { createWalletsAndAddresses, ethersDebugMessages } = require('./inc/lib');

(async ()=>{
    const {
        rinkebyDeployKey
    } = await createWalletsAndAddresses(ethers.provider);

    const debugAttestorKey = '0x5f7bFe752Ac1a45F67497d9dCDD9BbDA50A83955';
    const debugIssuerKey = '0xbf9Ae773d7D724b9632564fbE2c782Cc2Ed8817c';
    const attestationKey = '';  //Insert here
    const issuerKey = '';       //Insert here

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

    //deploy Verification contract
    const VerifyAttestation = await ethers.getContractFactory("VerifyTicket");
    const verifyAttestation = await VerifyAttestation.deploy();
    await verifyAttestation.deployed();

    const AttestationMintable = await ethers.getContractFactory("AttestationMintable");
    const nftContract = await AttestationMintable.connect(rinkebyDeployKey).deploy(verifyAttestation.address, debugAttestorKey, debugIssuerKey);
    await nftContract.deployed();

    console.log("Verify Addr: " + verifyAttestation.address);
    console.log("NFT Addr: " + nftContract.address);
    console.log("Owner: " + rinkebyDeployKey.address);

    console.log('User balance: ' , ethers.utils.formatEther(await ethers.provider.getBalance(rinkebyDeployKey.address)), "\n");

})();
// npx hardhat run scripts/deploy.js --network rinkeby