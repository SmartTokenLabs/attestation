import React, { useState, useEffect } from 'react';
import './App.css';
import { Authenticator, Negociator } from './TokenScript';
import Web3 from 'web3';
import Card from './Card';

// https://web3js.readthedocs.io/en/v1.2.0/web3-eth-accounts.html#id15
// https://github.com/ethereumjs/ethereumjs-util

function App() {

  // Connect to Ganache
  let web3 = new Web3('HTTP://127.0.0.1:7545');
  // Tokens, default to []
  let [tokens, setTokens] = useState([]);
  // 
  useEffect(() => {
    Negociator.getTokenInstances().then((tokens) => {
      setTokens(tokens);
      // Sign a message
      const signature = web3.eth.accounts.sign('Some data', '35335e2eac26772c5b1aed0114f7f635b99eb17fe8ef37cd68edd7acf093fa9c');
      console.log(signature);
      // Get the Public key of the signed message
      const signatureRecover = web3.eth.accounts.recover(signature);
      console.log(signatureRecover);
    }, (error) => {
      console.log(error);
    });
  }, []);
  return (
    <div>
      <Card tokens={tokens} />
    </div>
  );
}

export default App;
