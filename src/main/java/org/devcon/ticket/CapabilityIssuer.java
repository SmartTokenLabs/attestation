package org.devcon.ticket;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.SignatureUtility;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * Issues a long-term JWT to approve-list a specific domain to give it access to the DevCon ticket API.
 * Specifically the website who holds the token will be able to access a set of specific tasks (methods).
 *
 * This is specifically going to allow a third party site to open an iframe to ticket.devcon
 * in order to access the ticket secret stored in the local cache to construct a useDevconTicket request.
 */
public class CapabilityIssuer extends CapabilityCommon {
  private final KeyPair signingKeys;
  private final URL verifierDomain;

  public CapabilityIssuer(AsymmetricCipherKeyPair signingKeys, String verifierDomain) throws MalformedURLException {
    this.signingKeys = SignatureUtility.convertBouncyCastleKeysToJavaKey(signingKeys);
    this.verifierDomain = new URL(verifierDomain);
  }

  public String makeToken(String domain, Set<String> tasks, int expirationTimeInDays) throws MalformedURLException {
    URL urlDomain = new URL(domain);
    String flattenedTasks = flattenSet(tasks);
    long currentTime = System.currentTimeMillis();
    long expirationInMs = currentTime + (long) expirationTimeInDays * 24l * 60l * 60l * 1000l;
    return buildSignedToken(urlDomain, flattenedTasks, expirationInMs, currentTime);
  }

  String buildSignedToken(URL domain, String flattenedTasks, long expirationTimeInMs, long creationTimeInMs) {
    Builder builder = JWT.create();
    // Only withAudience, withSubject, withIssuer, withExpiresAt, withNotBefore and withClaim(tasksClaimName) are required
    builder.withClaim(TasksClaimName, flattenedTasks);
    // Both the issuer and verifier is the same
    builder.withAudience(verifierDomain.toString());
    builder.withIssuer(verifierDomain.toString());
    builder.withSubject(domain.toString());
    builder.withNotBefore(new Date(creationTimeInMs));
    builder.withExpiresAt(new Date(expirationTimeInMs));
    // withIssuedAt and withJWTId are OPTIONAL
    builder.withIssuedAt(new Date(creationTimeInMs));
    builder.withJWTId(getJWTID(domain.toString(), flattenedTasks, expirationTimeInMs, creationTimeInMs));
    return builder.sign(getAlgorithm(signingKeys.getPublic(), signingKeys.getPrivate()));
  }

  String flattenSet(Set<String> tasks) {
    if (tasks.size() == 0) {
      throw new IllegalArgumentException("At least one task must be assigned");
    }
    StringBuilder flattenedList = new StringBuilder();
    for (String task : tasks) {
      String normalizedTask = task.toLowerCase().trim();
      if (normalizedTask.contains(",")) {
        throw new IllegalArgumentException("A task contains a ',' which is not permitted");
      }
      flattenedList.append(normalizedTask).append(',');
    }
    String unprunedResult = flattenedList.toString();
    // Remove trailing ','
    return unprunedResult.substring(0, unprunedResult.length()-1);
  }

  private String getJWTID(String domain, String flattenedTasks, long expirationTime, long currentTime) {
    ByteBuffer toHash = ByteBuffer.allocate(domain.length() + TasksClaimName.length() +
        flattenedTasks.length() + 2 * (Long.SIZE / 8));
    toHash.put(domain.getBytes(StandardCharsets.UTF_8));
    toHash.put(TasksClaimName.getBytes(StandardCharsets.UTF_8));
    toHash.put(flattenedTasks.getBytes(StandardCharsets.UTF_8));
    toHash.putLong(expirationTime);
    toHash.putLong(currentTime);

    byte[] digest = AttestationCrypto.hashWithKeccak(toHash.array());
    return Base64.getEncoder().encodeToString(digest);
  }
}
