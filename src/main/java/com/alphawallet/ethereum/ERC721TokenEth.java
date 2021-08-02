package com.alphawallet.ethereum;

import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ERC721TokenEth extends DynamicStruct
{
    public Address address;
    public Uint256 tokenId;
    public DynamicBytes auth;

    public ERC721TokenEth(Address address, Uint256 tokenId, DynamicBytes bytes)
    {
        super(address, tokenId, bytes);
        this.address = address;
        this.tokenId = tokenId;
        this.auth = bytes;
    }

    public ERC721TokenEth(String address, String tokenId, byte[] bytes)
    {
        super(new Address(address), new Uint256(new BigInteger(tokenId)), new DynamicBytes(bytes));
        this.address = new Address(address);
        this.tokenId = new Uint256(new BigInteger(tokenId));
        this.auth = new DynamicBytes(bytes);
    }

    @Override
    public List<Type> getValue()
    {
        List<Type> tList = new ArrayList<>();
        tList.add(address);
        tList.add(tokenId);

        return tList;
    }

    @Override
    public String toString()
    {
        return "Token: " + address.toString() + " ID: " + tokenId.getValue().toString();
    }


    @Override
    public String getTypeAsString() {
        return "ERC721TokenEth";
    }
}
