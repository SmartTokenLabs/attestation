package org.devcon.ticket;

import com.alphawallet.attestation.core.SignatureUtility;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Verified a long-term JWT that has been issued to a specific domain in order to give it access to the DevCon ticket API.
 *
 * This is specifically going to be used to allow a third party site to open an iframe to ticket.devcon
 * in order to access the ticket secret stored in the local cache to construct a useDevconTicket request.
 */
public class CapabilityValidator extends CapabilityCommon{
  private final PublicKey verifyingKey;
  private final URL verifierDomain;
  private final Verification verification;

  public CapabilityValidator(AsymmetricKeyParameter verifyingKey, String verifierDomain) throws MalformedURLException {
    this.verifyingKey = SignatureUtility.convertPublicBouncyCastleKeyToJavaKey(verifyingKey);
    this.verifierDomain = new URL(verifierDomain);
    this.verification = JWT.require(getAlgorithm(this.verifyingKey, null))
        .withAudience(this.verifierDomain.toString())
        .withIssuer(this.verifierDomain.toString());
  }

  public boolean validateRequest(String jsonInput, String domain, Set<String> tasksThatMustBePresent) {
    try {
      URL domainUrl = new URL(domain);
      // Note that we already have added Audience, Issuer and that time validity and signature are
      // always verified implicitly.
      JWTVerifier verifier = verification.withSubject(domainUrl.toString()).build();
      DecodedJWT jwt = JWT.decode(jsonInput);
      jwt = verifier.verify(jwt);
      return verifyTasks(jwt, tasksThatMustBePresent);
    } catch (Exception e) {
      return false;
    }
  }

  private boolean verifyTasks(DecodedJWT jwt, Set<String> tasksThatMustBePresent) {
    String tasksString = jwt.getClaim(TasksClaimName).asString();
    Set<String> tasksInJwt = new HashSet<String>(Arrays.asList(tasksString.split(",")));
    Set<String> trimmedTasksThatMustBePresent = tasksThatMustBePresent.stream().
        map(s -> s.toLowerCase().trim()).collect(Collectors.toSet());
    return tasksInJwt.containsAll(trimmedTasksThatMustBePresent)
        && tasksThatMustBePresent.size() > 0;
  }

}
