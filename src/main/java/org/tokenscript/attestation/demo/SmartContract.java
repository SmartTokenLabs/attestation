package org.tokenscript.attestation.demo;

import com.alphawallet.ethereum.ERC721Token;
import com.alphawallet.token.tools.Numeric;
import org.tokenscript.attestation.FullProofOfExponent;
import org.tokenscript.attestation.ProofOfExponent;

import org.tokenscript.attestation.SignedIdentifierAttestation;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.alphawallet.ethereum.AttestationReturn;
import com.alphawallet.ethereum.TicketAttestationReturn;
import okhttp3.OkHttpClient;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.http.HttpService;

import static org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction;

public class SmartContract {
  private static final String ATTESTATION_CHECKING_CONTRACT = "0xBfF9E858796Bc8443dd1026D14Ae018EfBE87aD5";
  private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
  private static final String ATTESTATION_VERIFICATION_CONTRACT = "0xE5Eb8348f5dFcA8D6BF82A0DBcA461110F9FE1c9";
  private static final String TICKET_VERIFICATION_CONTRACT = "0x2dbBfF82B466fA76e6B1AD81A4C40E0BbA109ff9";


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

  public List<Address> getAttestationAddresses(SignedIdentifierAttestation signedAttestation)
  {
    Function function = verifyPublicAttestation(signedAttestation.getDerEncoding());
    return callAddrFunction(function);
  }

  public TicketAttestationReturn callVerifyTicketAttestation(byte[] attestation) throws Exception
  {
    return runVerifyTicketAttestationSC(verifyTicketAttestation(attestation));
  }

  public TicketAttestationReturn callVerifyTicketAttestation(byte[] attestation, String attestor, String issuer) throws Exception {
    return runVerifyTicketAttestationSC(verifyTicketAttestation(attestation, attestor, issuer));

  }

  private TicketAttestationReturn runVerifyTicketAttestationSC(Function function) {
    Web3j web3j = getRinkebyWeb3j();
    String result = callSmartContractFunction(web3j, function, TICKET_VERIFICATION_CONTRACT);
    List<Type> responseValues = FunctionReturnDecoder.decode(result, function.getOutputParameters());
    TicketAttestationReturn retVal = new TicketAttestationReturn();

    if (responseValues.size() == 4) {
      retVal.subjectAddress = responseValues.get(0).getValue().toString();
      retVal.conferenceId = (byte[]) responseValues.get(2).getValue();
      retVal.ticketId = (byte[]) responseValues.get(1).getValue();
      retVal.attestationValid = (boolean) responseValues.get(3).getValue();
    } else if (responseValues.size() > 4) {
      retVal.attestorAddress = responseValues.get(0).getValue().toString();
      retVal.issuerAddress = responseValues.get(1).getValue().toString();
      retVal.subjectAddress = responseValues.get(2).getValue().toString();
      retVal.ticketId = (byte[]) responseValues.get(3).getValue();
      retVal.conferenceId =  (byte[]) responseValues.get(4).getValue();
      retVal.attestationValid = (boolean) responseValues.get(5).getValue();
    }

    return retVal;
  }

  public AttestationReturn callVerifyNFTAttestation(byte[] att, String sender)
  {
    Web3j web3j = getRinkebyWeb3j();
    Function function = verifyNFTAttestation(att, sender);
    String result = callSmartContractFunction(web3j, function, ATTESTATION_VERIFICATION_CONTRACT);
    List<Type> responseValues = FunctionReturnDecoder.decode(result, function.getOutputParameters());
    AttestationReturn retVal = new AttestationReturn();

    if (responseValues.size() == 5)
    {
      List<ERC721Token> tokens = (List<ERC721Token>)responseValues.get(0).getValue();
      retVal.ercToken = tokens.toArray(new ERC721Token[0]);

      retVal.identifier = responseValues.get(1).getValue().toString();
      retVal.ownerAddress = responseValues.get(2).getValue().toString();
      retVal.attestorAddress = responseValues.get(3).getValue().toString();
      retVal.isValid = (boolean)responseValues.get(4).getValue();
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
    Web3j web3j = getRinkebyWeb3j();
    List<Address> addrList = new ArrayList<>();

    try
    {
      String responseValue = callSmartContractFunction(web3j, function, ATTESTATION_VERIFICATION_CONTRACT);
      List<Type> responseValues = FunctionReturnDecoder.decode(responseValue, function.getOutputParameters());

      if (responseValues.size() == 3 && responseValues.get(0) instanceof Address)
      {
        addrList.add((Address)responseValues.get(0));
        addrList.add((Address)responseValues.get(2));
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

  private static Function verifyPublicAttestation(byte[] encoding) {
    return new Function(
            "verifyPublicAttestation",
            Arrays.asList(new DynamicBytes(encoding), new Uint256(BigInteger.ZERO)),
            Arrays.asList(new TypeReference<Address>() {}, new TypeReference<Utf8String>() {}, new TypeReference<Address>() {}));
  }

  private static Function verifyNFTAttestation(byte[] encoding, String sender) {
    return new Function(
            "verifyNFTAttestation",
            Arrays.asList(new DynamicBytes(encoding),
                    new org.web3j.abi.datatypes.Address(160, sender)),
            Arrays.<TypeReference<?>>asList(new TypeReference<DynamicArray<ERC721Token>>() {},
                    new TypeReference<Utf8String>() {}, //Identifier
                    new TypeReference<Address>() {},    //subject
                    new TypeReference<Address>() {},    //attestor
                    new TypeReference<Bool>() {}));     //valid NFT signature by subject
  }

  //function verifyTicketAttestation(bytes memory attestation) public pure
  //  returns(address payable subject, bytes memory ticketId, address issuer, address attestor)
  private static Function verifyTicketAttestation(byte[] encoding) {
    return new Function(
            "verifyTicketAttestation",
            Arrays.asList(new DynamicBytes(encoding)),
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>() {}, //Attestor
                    new TypeReference<Address>() {},      //Issuer
                    new TypeReference<Address>() {},      //Subject
                    new TypeReference<DynamicBytes>() {},  //TicketId
                    new TypeReference<DynamicBytes>() {},  //ConferenceId
                    new TypeReference<Bool>() {}
            ));
  }

  /*
  address subject, bytes memory ticketId, bytes memory conferenceId, bool attestationValid
   */
  private static Function verifyTicketAttestation(byte[] encoding, String attestor, String issuer) {
    return new Function(
            "verifyTicketAttestation",
            Arrays.asList(new DynamicBytes(encoding),
                    new org.web3j.abi.datatypes.Address(160, attestor),
                    new org.web3j.abi.datatypes.Address(160, issuer)),
            Arrays.<TypeReference<?>>asList(
                    new TypeReference<Address>() {},      //Subject
                    new TypeReference<DynamicBytes>() {},  //TicketId
                    new TypeReference<DynamicBytes>() {},  //ConferenceId
                    new TypeReference<Bool>() {} //attestation valid
            ));
  }

  protected static org.web3j.abi.datatypes.DynamicArray<?> getERC721Array(ERC721Token token)
  {
    return new org.web3j.abi.datatypes.DynamicArray<>(
            ERC721Token.class, Collections.singletonList(token));
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
