// Defining bytecode and abi from original contract on mainnet to ensure bytecode matches and it produces the same pair code hash

module.exports = async function ({ ethers, getNamedAccounts, deployments, getChainId }) {
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();

  /** These values are hard-coded at the moment */
  const verficationAddress = '0x1e73f42fc513fc9f13d06525ee7ce1be2c087d7a';
  const attestorKey = '0x538080305560986811c3c1a2c5bcb4f37670ef7e';
  const issuerKey = '0x17c0b3b51a75f1a001f255a7cad4fa45529cac20'

  await deploy('AttestationMintableEnumerable', {
    from: deployer,
    log: true,
    args: [verficationAddress, attestorKey, issuerKey],
    deterministicDeployment: false
  });
};

module.exports.tags = ['AttestationMintableEnumerable'];
