const Authenticator = {
  init: () => {
    return "Hello Authenticator";
  },
  authenticateAddress: async function (ownerAddress) {
    return true;
  },
  findOwner: async function () {
    // Mock for now
    tokenMock[0].token.ownerAddress = 2;
    return tokenMock[0].token.ownerAddress;
  },
  authenticate: async function () {
    return "Authenticated"
  }
}

export {
  Authenticator
};