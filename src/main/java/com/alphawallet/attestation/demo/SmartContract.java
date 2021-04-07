package com.alphawallet.attestation.demo;

import static org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction;

import com.alphawallet.attestation.FullProofOfExponent;
import com.alphawallet.attestation.ProofOfExponent;
import com.alphawallet.attestation.SignedAttestation;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
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

  public List<Address> getAttestationAddresses(SignedAttestation signedAttestation)
  {
    Function function = decodeAttestation(signedAttestation.getDerEncoding());
    return callAddrFunction(function);
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
    HttpService nodeService = new HttpService("https://kovan.infura.io/v3/da3717f25f824cc1baa32d812386d93f", buildClient(), false);
    return Web3j.build(nodeService);
  }
}
