pragma solidity ^0.4.18;

contract CryptoTool{

  function hmacsha256(bytes key, bytes message) public pure returns (bytes32) {
    bytes32 keyleft;
    bytes32 keyright;
    uint index;
    uint blocksize = 64;
    if(key.length>blocksize){
      keyleft = sha256(key);
    }else{
      for(index=0;index<key.length&&index<32;index++){
        keyleft |= bytes32(uint(key[index]) * 2**(8 * (31 - index)));
      }
      for(index=32;index<key.length&&index<64;index++){
        keyright != bytes32(uint(key[index]) * 2**(8 * (63 - index)));
      }
    }
    //0011 0110 ....
    bytes32 ipad = 0x3636363636363636363636363636363636363636363636363636363636363636;
    //0101 1100 ....
    bytes32 opad = 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c;
    //hash(XOR opad || hash(XOR ipad||message))
    return sha256(opad ^ keyleft, opad ^ keyright, sha256(ipad ^ keyleft, ipad ^ keyright, message));
  }

  function stringToBytes(string source) public pure returns (bytes) {
    bytes memory convertTobytes = bytes(source);
    require(convertTobytes.length>0);
    return convertTobytes;
  }

  function testhmacsha256() public pure returns (bytes32) {
    bytes memory key=stringToBytes("key");
    bytes memory message=stringToBytes("The quick brown fox jumps over the lazy dog");
    //expected: f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
    return hmacsha256(key, message);
  }

}
