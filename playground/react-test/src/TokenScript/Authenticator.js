import tokenMock from './tokenMock';

const Authenticator = {
  authenticateAddress: function async(ownerAddress) {
    return new Promise((resolve, reject) => {
      return resolve(true);
    });
  },
  findOwner: function async() {
    return new Promise((resolve, reject) => {
      tokenMock[0].token.ownerAddress = 2;
      return resolve(tokenMock[0].token.ownerAddress);
    });
  },
  authenticate: function async() {
    return new Promise((resolve, reject) => {
      return resolve("Authenticated");
    });
  }
}

export {
  Authenticator
};