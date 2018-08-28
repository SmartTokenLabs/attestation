pragma solidity ^0.4.17;
import "./AttestationFramework";
contract AuthorisedAttestors {

  address[] authorities;

  constructor(address[] initialAuthorities) public
  {
      authorities = initialAuthorities;
  }

  function addAuthority(address newAuthority) public
  {
      bool isAuthorised = AttestationFramework.isAuthorised(msg.sender);
      require(isAuthorised);
      authorities.push(newAuthority);
  }

  function isAuthorised(address attestor) internal view returns(bool)
  {
      for(uint i = 0; i < authorities.length; i++)
      {
          if(attestor == authorities[i])
          {
              return true;
          }
      }
      return false;
  }

}
