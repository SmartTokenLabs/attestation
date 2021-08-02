package org.devcon.ticket;

import com.alphawallet.attestation.core.ExceptionUtil;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CapabilityCommon {
  private static final Logger logger = LogManager.getLogger(CapabilityCommon.class);

  public static final String TasksClaimName = "org.devcon.ticket.capability";

  protected Algorithm getAlgorithm(PublicKey pk, PrivateKey secretKey) {
    // SHA 512 is always used for hashing
    if (pk instanceof ECPublicKey) {
      return Algorithm.ECDSA512((ECPublicKey) pk, (ECPrivateKey) secretKey);
    } else if (pk instanceof RSAPublicKey) {
      return Algorithm.RSA512((RSAPublicKey) pk, (RSAPrivateKey) secretKey);
    } else {
      throw ExceptionUtil.throwException(logger,
          new UnsupportedOperationException("The key used to sign with is not EC or RSA which are currently the only supported types."));
    }
  }
}
