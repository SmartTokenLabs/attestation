package com.alphawallet.attestation.demo;

import static org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.ProofOfExponent;
import com.alphawallet.attestation.SignedIdentityAttestation;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.alphawallet.ethereum.AttestationReturn;
import com.alphawallet.ethereum.ERC721TokenEth;

import okhttp3.OkHttpClient;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.http.HttpService;

public class SmartContract {
  private static final String ATTESTATION_CHECKING_CONTRACT = "0xBfF9E858796Bc8443dd1026D14Ae018EfBE87aD5";
  private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
  private static final String ATTESTATION_VALIDATION_CONTRACT = "0x229fEdAb1313BB85b61A729e65aE2363A1441878";

  private static final String ATTESTATION_VERIFICATION_CONTRACT = "0x157b8976726177C29341A30176a5a8fa03FE7778";

  public boolean verifyEqualityProof(byte[] com1, byte[] com2, ProofOfExponent pok) throws Exception
  {
    Function function = verifyEncoding(com1, com2, pok.getDerEncoding());
    return callFunction(function);
  }

  public boolean usageProofOfExponent(FullProofOfExponent exp)
  {
    Function function = checkEncoding(exp.getDerEncoding());
    return callFunction(function);
  }

  public List<Address> getAttestationAddresses(SignedIdentityAttestation signedAttestation)
  {
    Function function = decodeAttestation(signedAttestation.getDerEncoding());
    return callAddrFunction(function);
  }

  public AttestationReturn callVeryifyNFTAttestation(byte[] att, String sender)
  {
    Web3j web3j = getRinkebyWeb3j();
    Function function = verifyNFTAttestation(att, sender);
    String result = callSmartContractFunction(web3j, function, ATTESTATION_VERIFICATION_CONTRACT);
    List<Type> responseValues = FunctionReturnDecoder.decode(result, function.getOutputParameters());
    AttestationReturn retVal = new AttestationReturn();

    if (responseValues.size() > 0) {
      for (Type t : responseValues) {
        switch (t.getTypeAsString())
        {
          case "ERC721TokenEth[]":
            List<ERC721TokenEth> tokens = (List<ERC721TokenEth>)t.getValue();
            retVal.ercToken = tokens.toArray(new ERC721TokenEth[0]);
            break;
          case "string":
            retVal.identity = t.getValue().toString();
            break;
          case "address":
            retVal.ownerAddress = t.getValue().toString();
            break;
          case "bool":
            retVal.isValid = (boolean)t.getValue();
            break;
        }
      }
    }

    return retVal;
  }

  private boolean callFunction(Function function)
  {
    Web3j web3j = getWeb3j();

    boolean result = false;

    try
    {
      String responseValue = callSmartContractFunction(web3j, function, ATTESTATION_CHECKING_CONTRACT);
      List<Type> responseValues = FunctionReturnDecoder.decode(responseValue, function.getOutputParameters());

      if (!responseValues.isEmpty())
      {
        if (!((boolean) responseValues.get(0).getValue()))
        {
          System.out.println("Check failed");
        }
        else
        {
          System.out.println("Check passed");
          result = true;
        }
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }

    return result;
  }

  private List<Address> callAddrFunction(Function function)
  {
    Web3j web3j = getWeb3j();
    List<Address> addrList = new ArrayList<>();

    try
    {
      String responseValue = callSmartContractFunction(web3j, function, ATTESTATION_VALIDATION_CONTRACT);
      List<Type> responseValues = FunctionReturnDecoder.decode(responseValue, function.getOutputParameters());

      if (responseValues.size() == 2 && responseValues.get(0) instanceof Address)
      {
        addrList.add((Address)responseValues.get(0));
        addrList.add((Address)responseValues.get(1));
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }

    return addrList;
  }

  private String callSmartContractFunction(Web3j web3j,
      Function function, String contractAddress)
  {
    String encodedFunction = FunctionEncoder.encode(function);

    try
    {
      org.web3j.protocol.core.methods.request.Transaction transaction
          = createEthCallTransaction(ZERO_ADDRESS, contractAddress, encodedFunction);
      EthCall response = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();

      return response.getValue();
    }
    catch (IOException e)
    {
      return null;
    }
    catch (Exception e)
    {
      e.printStackTrace();
      return null;
    }
  }

  private static Function checkEncoding(byte[] encoding) {
    return new Function(
            "decodeAttestation",
            Collections.singletonList(new DynamicBytes(encoding)),
            Collections.singletonList(new TypeReference<Bool>() {}));
  }

  private static Function verifyEncoding(byte[] com1, byte[] com2, byte[] encoding) {
    return new Function(
            "verifyEqualityProof",
            Arrays.asList(new DynamicBytes(com1), new DynamicBytes(com2), new DynamicBytes(encoding)),
            Collections.singletonList(new TypeReference<Bool>() {}));
  }

  private static Function testAttestationCall(byte[] encoding) {
    return new Function(
            "testAttestationCall",
            Arrays.asList(new DynamicBytes(encoding)),
            Collections.singletonList(new TypeReference<Bool>() {}));
  }

  private static Function decodeAttestation(byte[] encoding) {
    return new Function(
            "decodeAttestation",
            Arrays.asList(new DynamicBytes(encoding)),
            Arrays.asList(new TypeReference<Address>() {}, new TypeReference<Address>() {}));
  }

  private static Function verifyPublicAttestation(byte[] encoding) {
    return new Function(
            "verifyPublicAttestation",
            Arrays.asList(new DynamicBytes(encoding), new Uint256(BigInteger.ZERO)),
            Arrays.asList(new TypeReference<Address>() {}, new TypeReference<Utf8String>() {}, new TypeReference<Bool>() {}));
  }

  private static Function verifyNFTAttestation(byte[] encoding, String sender) {
    return new Function(
            "verifyNFTAttestation",
            Arrays.asList(new DynamicBytes(encoding),
                    new org.web3j.abi.datatypes.Address(160, sender)),
            Arrays.<TypeReference<?>>asList(new TypeReference<DynamicArray<ERC721TokenEth>>() {}, new TypeReference<Utf8String>() {}, new TypeReference<Address>() {}, new TypeReference<Bool>() {}));
  }

  protected static org.web3j.abi.datatypes.DynamicArray<?> getERC721Array(ERC721TokenEth token)
  {
    return new org.web3j.abi.datatypes.DynamicArray<>(
            ERC721TokenEth.class, Collections.singletonList(token));
  }

  private OkHttpClient buildClient()
  {
    return new OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build();
  }

  private Web3j getWeb3j()
  {
    //Infura
    HttpService nodeService = new HttpService("https://kovan.infura.io/v3/b567f041158a4676898698c2d4c5f478", buildClient(), false);
    return Web3j.build(nodeService);
  }

  private Web3j getRinkebyWeb3j()
  {
    //Infura
    HttpService nodeService = new HttpService("https://rinkeby.infura.io/v3/b567f041158a4676898698c2d4c5f478", buildClient(), false);
    return Web3j.build(nodeService);
  }
}
