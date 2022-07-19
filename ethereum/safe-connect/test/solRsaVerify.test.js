// const { expect } = require('chai');
// const { ethers } = require('hardhat');

// /**
//  * We assume loan currency is native coin
//  */
// describe('SolRsaVerifyTest', function () {
//   before(async function () {
//     this.SolRsaVerifyTest = await ethers.getContractFactory('SolRsaVerifyTest');
//   });

//   beforeEach(async function () {
//     this.solRsaVerifyTest = await (
//       await this.SolRsaVerifyTest.deploy()
//     ).deployed();
//   });

//   it('RSA signature', async function () {
//     //const msg = 'hello world';
//     //const hexMsg1 = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(msg));

//     // const modulus = "0xB793F2F926170FAD768F8B1A5769A2243B4CDCAC4780194F59B39E1A2ABC3BB8EA42DB495D17BEC7F7072A11ED4FA510E75A7886A5DB6F71B7AFCA0090CA079889D18AF0669829ED29A8E21D0C09BD19CAAF2FE2CC8121BFC5687AC6698E3022F468A481426486CAD263BE1A119491E034A6E1AB78F19C066D4145A50F9ECFF7";
//     // const exponent= "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
//     // const signature = "0x57a0d6a185924d9d579b3ab319fe512331cb0bc6ef2da7d5285cbd06844f5c44662cae2e41ee5020893d6690e34b50a369a78250ae81ba6d708560535ef7cff0299f2ba070b096a9a76e84cf9c902b5e367b341ee166f5fc325dd08a3d971d96d528937f617a1eaf2250c56c4edca80c65970d54fe2492a19468bd32166b3c32";

//     //const modulus = "0xFAEEFC2BE95C7BD5FA106BF2304D2FF1471310C303AAF05B1C68BB205564E3B7195C162002B3BB2D529AEFBD48FB810A978F047F87978DCC28680A56692A396ECF92A69BE1B78031ECB0FE0B0E4B37FC1837A7696499A30142F435745D15ADDE7A1201C6DA20FF797A9B1492464BB6FDB18BBF50AFCC48881566EC1CD3298795";
//     //const exponent= "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
//     //const signature = "0x1cf96164b68c76598e618d3fb70599e9360f143f274a5a19616068482afb4ab9529e59457fee16b60494dfcfbbc637cb8af5ba6396afc1851158909382cb4294269778085ba3c4cba01aba3ed44599f9f3e64da57750e78c2c38bd3f2f03984d62b6506252f612e43d4d1040ae4da685b050fe27d9cb6457f8269cf17d385536";

//     // Link attestation signed payload
//     const hexMsg1 = "0x3082013d0414cff805b714b24b3dd30cb4a1bea3745e5c5e73efa1820115308201113081c630819f300d06092a864886f70d010101050003818d0030818902818100b3ad78d0b9c3a0cee4e174aff68670f185484c2b2b12eaf1159cbf35b1a4aca051e8c55596ac20f866ca2936ace92e80b8e4fc1e54231e1599f4970cebd967d1a3c22246ae1e2a92a16f03f5154186a5c3b92fecb1cc96d8a133ad34ac91995db10efe2ee3ecff2491f5cebc298ea0deebe925e7a39d91435ff5b4701d754351020301000104148646df47d7b16bf9c13da881a2d8cdacda8f5490300c020462b52546020462b53356300206000342000a22c6493ea332aae6ae4487f5cff2f6fecc73f9f1bfb011ac4709a149b6ab0f70b7c336c6d2684af7853c589ba7e8ebd2912d53260d898cb4d87778191280451c300c020462b52546020462b53356";

//     const modulus =   "0xb3ad78d0b9c3a0cee4e174aff68670f185484c2b2b12eaf1159cbf35b1a4aca051e8c55596ac20f866ca2936ace92e80b8e4fc1e54231e1599f4970cebd967d1a3c22246ae1e2a92a16f03f5154186a5c3b92fecb1cc96d8a133ad34ac91995db10efe2ee3ecff2491f5cebc298ea0deebe925e7a39d91435ff5b4701d754351";
//     const exponent =  "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
//     const signature = "0x39fe82b186160e1da096c3641a5925b5a288b749ca84d7ffbf6dbf46faa8feaf3632357869b4d530928506f32af16692319778f797379bd9dc843830c1f3acd134fd2c03e7a0f663ba9e2c2f965a99ac9bffec47e42e592c7f3ea37b82d0eece04e5c1fccb91ec4ba8fc6f5333287d4a7dc551c1fa8bd29b24dcdb65ba22f3f7";

//     const result = await this.solRsaVerifyTest.pkcs1Sha256VerifyRawTest(hexMsg1, signature, exponent, modulus);

//     console.log('result', result.toString());

//     expect(result).to.be.equal(0);

//     const tx = await this.solRsaVerifyTest.pkcs1Sha256VerifyRawTestGasEstimate(hexMsg1, signature, exponent, modulus);
//     const txResult = await (tx.wait());

//     console.log('RSA txResult ==>', txResult.gasUsed.toString());
//     console.log('RSA txResult1 ==>', txResult.cumulativeGasUsed.toString());
//   });
// });
