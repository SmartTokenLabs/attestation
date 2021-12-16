const { ethers } = require("hardhat");
require("dotenv").config();
const { PRIVATE_KEY, PRIVATE_KEY_RINKEBY, PRIVATE_KEY_RETORT, PRIVATE_KEY_MAIN } = process.env;

const env_keys_required = [
    "PRIVATE_KEY",
    "PRIVATE_KEY_RINKEBY",
	"PRIVATE_KEY_RETORT",
	"PRIVATE_KEY_MAIN"
];

function calcContractAddress(sender, nonce)
{
    const rlp = require('rlp');
    const keccak = require('keccak');

    var input_arr = [ sender.address, nonce ];
    var rlp_encoded = rlp.encode(input_arr);

    var contract_address_long = keccak('keccak256').update(rlp_encoded).digest('hex');

    var contract_address = contract_address_long.substring(24); //Trim the first 24 characters.
    return "0x" + contract_address;
}

function requiredEnvKeysExists(){
    let $checkOk = true;

    env_keys_required.forEach((item) => {
        try {
            if (!eval(item)) throw new Error(`"${item}" not configured. check your .env file`)
        } catch (e) {
            console.error(e.message);
            $checkOk = false;
        }
    })
    return $checkOk;
}

function ethersDebugMessages(message, e){
    console.error(message);
    console.error('Reason : ' + e.reason);
    console.error('Code   : ' + e.code);
    console.error('Method : ' + e.method);
    console.error('Error  : ' + e.error);
}

async function createWalletsAndAddresses(provider){

    // check if all required keys exist in the ethereum/.env file
    if (!requiredEnvKeysExists()) return;

    const [owner] = await ethers.getSigners();

    const rinkebyDeployKey = new ethers.Wallet(PRIVATE_KEY_RINKEBY, provider);
    const rinkebyDeployKey2 = new ethers.Wallet(PRIVATE_KEY, provider);
    const mumbaiDeployKey = new ethers.Wallet(PRIVATE_KEY_RETORT, provider);
    const mainDeployKey = new ethers.Wallet(PRIVATE_KEY_MAIN, provider);

    // console.log( 'rinkebyDeployKey address ' , rinkebyDeployKey.address);
    console.log( 'rinkebyDeployKey2 address ' , rinkebyDeployKey2.address);
    // console.log( 'mumbaiDeployKey address ' , mumbaiDeployKey.address);
    // console.log( 'mainDeployKey address ' , mainDeployKey.address);

    const { chainId } = await ethers.provider.getNetwork()

    console.log( 'Chain Id: ' , chainId);

    if (chainId == 31337 || chainId == 1337) { //default HH ganache Id for testing, provide balances
        await owner.sendTransaction({
            to: rinkebyDeployKey2.address,
            value: ethers.utils.parseEther("3.0")
        });

        // await owner.sendTransaction({
        //     to: retortDeployKey.address,
        //     value: ethers.utils.parseEther("3.0")
        // });

        // await owner.sendTransaction({
        //     to: myNFTDeployKey.address,
        //     value: ethers.utils.parseEther("3.0")
        // });

        // await owner.sendTransaction({
        //     to: remixDeployKey.address,
        //     value: ethers.utils.parseEther("3.0")
        // });
    }

    let startBalance2 = await ethers.provider.getBalance(rinkebyDeployKey2.address);
    console.log( 'Balance ' , ethers.utils.formatEther(startBalance2));


    return {
        rinkebyDeployKey,
        rinkebyDeployKey2,
		mumbaiDeployKey,
		mainDeployKey
    }

}

module.exports = {
    createWalletsAndAddresses, ethersDebugMessages
}
