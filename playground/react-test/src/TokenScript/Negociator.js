import tokenMock from './tokenMock';

const Negociator = {
  getTokenInstances: function async() {
    return new Promise((resolve, reject) => {
      return resolve(tokenMock);
    });
  }
}

export {
  Negociator
};