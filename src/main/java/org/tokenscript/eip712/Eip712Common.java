package org.tokenscript.eip712;

import com.alphawallet.token.web.service.CryptoFunctions;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.tokenscript.attestation.core.ExceptionUtil;
import org.tokenscript.attestation.core.Validateable;
import org.tokenscript.attestation.core.Verifiable;

/**
 * Common class for EIP712 JSON issuance and validation
 */
public abstract class Eip712Common {
  private static final Logger logger = LogManager.getLogger(Eip712Common.class);
  protected final CryptoFunctions cryptoFunctions;
  protected final ObjectMapper mapper;
  protected final Eip712Encoder encoder;

  public Eip712Common(Eip712Encoder encoder) {
    Security.addProvider(new BouncyCastleProvider());
    this.cryptoFunctions = new CryptoFunctions();
    this.mapper = new ObjectMapper();
    mapper.setSerializationInclusion(Include.NON_NULL);
    this.encoder = encoder;
  }

  public String getSignatureFromJson(String signedJson) {
    try {
      Eip712ExternalData data = mapper.readValue(signedJson, Eip712ExternalData.class);
      return data.getSignatureInHex();
    } catch (Exception e) {
      throw ExceptionUtil.makeRuntimeException(logger, "Could not recover signature from signed json", e);
    }
  }

  public static boolean isDomainValid(String domain) {
    try {
      // Check if we get a malformed exception
      new URL(domain);
    } catch (MalformedURLException e) {
      return false;
    }
    return true;
  }

  public static void checkAttestRequestVerifiability(Verifiable input) {
    if (!input.verify()) {
      throw new RuntimeException("Verification failed");
    }
  }
  public static void checkAttestRequestValidity(Validateable input) {
    if (!input.checkValidity()) {
      throw new RuntimeException("Validation failed");
    }
  }
}
