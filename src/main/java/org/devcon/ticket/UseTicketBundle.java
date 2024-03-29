package org.devcon.ticket;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.tokenscript.attestation.AttestedObject;
import org.tokenscript.attestation.Timestamp;
import org.tokenscript.attestation.core.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;

public class UseTicketBundle implements Verifiable {
  private static final Logger logger = LogManager.getLogger(UseTicketBundle.class);

  private final AttestedObject<Ticket> useTicket;
  private final UnpredictableNumberBundle un;
  private final byte[] signature;
  private final byte[] messageToSign;

  private final ObjectMapper jsonMapper;

  public UseTicketBundle(AttestedObject<Ticket> useTicket, UnpredictableNumberBundle un, AsymmetricKeyParameter signingKey) {
    this.jsonMapper = new ObjectMapper();

    this.useTicket = useTicket;
    this.un = un;
    this.messageToSign = computeMessage(un);
    this.signature = SignatureUtility.signPersonalMsgWithEthereum(getMessageToSign(), signingKey);
    constructorCheck();
  }

  public UseTicketBundle(AttestedObject<Ticket> useTicket, UnpredictableNumberBundle un, byte[] signature) {
    this.jsonMapper = new ObjectMapper();
    this.useTicket = useTicket;
    this.un = un;
    this.messageToSign = computeMessage(un);
    this.signature = signature;
    constructorCheck();
  }

  public UseTicketBundle(String jsonBundle, AsymmetricKeyParameter ticketIssuerPublicKey, AsymmetricKeyParameter attestorPublicKey) throws Exception {
    this.jsonMapper = new ObjectMapper();
    JsonUseTicketBundle decodedBundle = jsonMapper.readValue(jsonBundle, JsonUseTicketBundle.class);
    this.useTicket = new AttestedObject<>(decodedBundle.getUseTicketDer(), new DevconTicketDecoder(ticketIssuerPublicKey), attestorPublicKey);
    this.un = decodedBundle.getUn();
    this.messageToSign = computeMessage(un);
    this.signature = decodedBundle.getSignature();
    constructorCheck();
  }

  private void constructorCheck() {
    if (!verify()) {
      throw ExceptionUtil.throwException(logger,
          new IllegalArgumentException("Could not verify object"));
    }
  }

  private byte[] computeMessage(UnpredictableNumberBundle currentUn) {
    Date expirationDate = new Date(currentUn.getExpiration());
    String expirationString = Timestamp.getTimestampFormat().format(expirationDate);
    String messageToSignString =  "Authenticate towards \"" + currentUn.getDomain() + "\" using unpredictable number \"" + currentUn.getNumber()
        + "\" for an authentication valid until " + expirationString;
    return messageToSignString.getBytes(StandardCharsets.UTF_8);
  }

  public AttestedObject<Ticket> getUseTicket() {
    return useTicket;
  }

  public UnpredictableNumberBundle getUn() {
    return un;
  }

  public byte[] getSignature() {
    return signature;
  }

  public byte[] getMessageToSign() {
    return messageToSign;
  }

  public String getJsonBundle() throws JsonProcessingException {
    return jsonMapper.writeValueAsString(new JsonUseTicketBundle(useTicket.getDerEncoding(), un,
            signature));
  }

  public boolean validateAndVerify(UnpredictableNumberTool unt) {
    if (!useTicket.checkValidity()) {
      logger.error("Use ticket is not valid");
      return false;
    }
    if (!unt.validateUnpredictableNumber(un.getNumber(), un.getRandomness(), un.getExpiration(), un.getContext())) {
      logger.error("Unpredictable number is not valid ");
      return false;
    }
    if (!Arrays.equals(un.getNumber().getBytes(StandardCharsets.UTF_8), useTicket.getPok().getUnpredictableNumber())) {
      logger.error("Unpredictable number used in the UseTicket proof is different from the unpredictable number signed");
      return false;
    }
    return verify();
  }

  @Override
  public boolean verify() {
    if (!useTicket.verify()) {
      logger.error("UseTicket could not be verified");
      return false;
    }
    if (!SignatureUtility.verifyPersonalEthereumSignature(computeMessage(un), signature, useTicket.getAttestedUserKey())) {
      logger.error("Signature could not be verified");
      return false;
    }
    return true;
  }

  @JsonPropertyOrder({ "useTicketDer", "un", "signature"})
  private static class JsonUseTicketBundle {
    private byte[] useTicketDer;
    private UnpredictableNumberBundle un;
    private byte[] signature;

    public JsonUseTicketBundle() {}
    public JsonUseTicketBundle(byte[] useTicketDer, UnpredictableNumberBundle un,
        byte[] signature) {
      this.useTicketDer = useTicketDer;
      this.un = un;
      this.signature = signature;
    }

    public byte[] getUseTicketDer() {
      return useTicketDer;
    }

    public void setUseTicketDer(byte[] useTicketDer) {
      this.useTicketDer = useTicketDer;
    }

    public UnpredictableNumberBundle getUn() {
      return un;
    }

    public void setUn(UnpredictableNumberBundle un) {
      this.un = un;
    }

    public byte[] getSignature() {
      return signature;
    }

    public void setSignature(byte[] signature) {
      this.signature = signature;
    }

  }
}
