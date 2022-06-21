import { task } from 'hardhat/config';
import "@nomiclabs/hardhat-waffle";

require('@nomiclabs/hardhat-ethers');
require('@openzeppelin/hardhat-upgrades');

import 'hardhat-deploy';
import 'hardhat-deploy-ethers';

require("dotenv").config();

// Go to https://www.alchemyapi.io, sign up, create
// a new App in its dashboard, and replace "KEY" with its key
let { PRIVATE_KEY, ALCHEMY_API_KEY, ALCHEMY_RINKEBY_API_KEY, ALCHEMY_ROPSTEN_API_KEY } = process.env;

PRIVATE_KEY = PRIVATE_KEY ? PRIVATE_KEY : "0x2222453C7891EDB92FE70662D5E45A453C7891EDB92FE70662D5E45A453C7891";

// if not defined .env then set empty API keys, we dont use it for tests
ALCHEMY_API_KEY = ALCHEMY_API_KEY ? ALCHEMY_API_KEY : "";
ALCHEMY_RINKEBY_API_KEY = ALCHEMY_RINKEBY_API_KEY ? ALCHEMY_RINKEBY_API_KEY : "";
ALCHEMY_ROPSTEN_API_KEY = ALCHEMY_ROPSTEN_API_KEY ? ALCHEMY_ROPSTEN_API_KEY : "";

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async (args, hre) => {
  const accounts = await hre.ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
export default {
  solidity: {
    compilers: [
      {
        version: "0.8.0",
        settings: {
          optimizer: {
            enabled: true,

            runs: 200
          }
        }
      },{
        version: "0.8.4",
        settings: {
          optimizer: {
            enabled: true,

            runs: 200
          }
        }
      }
    ],
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "metadata", // <-- add this
        ]
      },
    },
  },
  namedAccounts: {
    deployer: {
      default: 0,
    },
    dev: {
      default: 1,
    },
  },
  networks: {
    // hardhat: {
    //   accounts: [
    //     {
    //       // balance updated from 21408160000000000 to 921408160000000000
    //       balance: "921408160000000000", // balance in WEI
    //       privateKey: `${PRIVATE_KEY}`
    //     },
    //     {
    //       // balance updated from 21408160000000000 to 921408160000000000
    //       balance: "921408160000000000", // balance in WEI
    //       privateKey: `${PRIVATE_KEY2}`
    //     },
    //   ]
    // },
    ropsten: {
      url: `https://eth-ropsten.alchemyapi.io/v2/${ALCHEMY_ROPSTEN_API_KEY}`,
      accounts: [`${PRIVATE_KEY}`]
    },
    rinkeby: {
      url: `https://eth-rinkeby.alchemyapi.io/v2/${ALCHEMY_RINKEBY_API_KEY}`,
      accounts: [`${PRIVATE_KEY}`]
    },
    mumbai: {
      url: `https://rpc-mumbai.maticvigil.com`, //ths RPC seems to work more consistently
      // "https://matic-mumbai.chainstacklabs.com",
      // "https://rpc-mumbai.maticvigil.com",
      // "https://matic-testnet-archive-rpc.bwarelabs.com"
      accounts: [`${PRIVATE_KEY}`]
    },
    mainnet: {
      url: `https://eth-mainnet.alchemyapi.io/v2/${ALCHEMY_API_KEY}`,
      accounts: [`${PRIVATE_KEY}`]
    },
    bsc: {
      url: `https://bsc-dataseed1.binance.org:443`,
      accounts: [`${PRIVATE_KEY}`]  
    },
    xdai: {
      url: `https://rpc.xdaichain.com/`,
      accounts: [`${PRIVATE_KEY}`]
    },
    polygon: {
      url: `https://matic-mainnet.chainstacklabs.com`,
      accounts: [`${PRIVATE_KEY}`]
    },
    arbrinkeby: {
      url: `https://rinkeby.arbitrum.io/rpc`,
      accounts: [`${PRIVATE_KEY}`]
    },
    optimistickovan: {
      url: `https://kovan.optimism.io/`,
      accounts: [`${PRIVATE_KEY}`]
    }
  },
  paths: {
    deploy: "deploy",
    deployments: "deployments"
  },
};
