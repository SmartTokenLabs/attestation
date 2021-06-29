package org.devcon.ticket;

import com.alphawallet.attestation.AttestedObject;
import com.alphawallet.attestation.core.SignatureUtility;
import com.alphawallet.attestation.core.Validateable;
import com.alphawallet.attestation.core.Verifiable;
import com.alphawallet.attestation.eip712.Timestamp;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class UseTicketBundle implements Verifiable, Validateable {
  private final AttestedObject useTicket;
  private final UnpredictableNumberBundle un;
  private final byte[] signature;
  private ObjectMapper jsonMapper;

  public UseTicketBundle(AttestedObject useTicket, UnpredictibleNumberTool unt, AsymmetricKeyParameter signingKey) {
    this.useTicket = useTicket;
    this.un = unt.getUnpredictibleNumberBundle();
    this.signature = SignatureUtility.signPersonalMsgWithEthereum(getMessageToSign(), signingKey);
    this.jsonMapper = new ObjectMapper();
  }

  public UseTicketBundle(AttestedObject useTicket, UnpredictableNumberBundle un, byte[] signature) {
    this.useTicket = useTicket;
    this.un = un;
    this.signature = signature;
    this.jsonMapper = new ObjectMapper();
  }

  public UseTicketBundle(String jsonBundle, UnpredictibleNumberTool unt, AsymmetricKeyParameter attestorPublicKey) {

  }

  public byte[] getMessageToSign() {
    Date expirationDate = new Date(un.getExpiration());
    String expirationString = Timestamp.TIMESTAMP_FORMAT.format(expirationDate);
    String messageToSignString =  "Authenticate towards \"" + un.getDomain() + "\" using unpredictable number \"" + un.getNumber()
        + "\" for an authentication valid until " + expirationString;
    return messageToSignString.getBytes(StandardCharsets.UTF_8);
  }

  public String getJsonBundle() throws Exception {
    return jsonMapper.writeValueAsString(Arrays.asList(useTicket.getDerEncoding(), un, getMessageToSign(), signature));
  }

  @Override
  public boolean checkValidity() {
    if (!useTicket.checkValidity()) {
      return false;
    }
    return true;
  }

  @Override
  public boolean verify() {
    if (!useTicket.verify()) {
      return false;
    }
    // verify signature on challenge and that challenge is valid
    return false;
  }
}
