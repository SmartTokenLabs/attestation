package dk.alexandra.stormbird.issuer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.junit.Test;

public class TestAttestation {
  public static final ECDomainParameters DOMAIN = new ECDomainParameters(Attestation.CURVE_PARAM.getCurve(), Attestation.CURVE_PARAM.getG(), Attestation.CURVE_PARAM.getN(), Attestation.CURVE_PARAM.getH());
  private static AsymmetricCipherKeyPair serverKeys, userKeys;
  private static String request, response;
  private static SecureRandom rand;

  @org.junit.BeforeClass
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    serverKeys = constructKeys(rand);
    userKeys = constructKeys(rand);
    request = Files.readString(Path.of("../test/verification_request.json"));
    response = Files.readString(Path.of("../test/verification_response.json"));
  }

  @Test
  public void testSunshine() throws IOException {
    Attestation att = new Attestation(serverKeys);
    byte[] requestJson = request.toString().getBytes(StandardCharsets.UTF_8);
    byte[] signature = SignatureUtil.sign(requestJson, userKeys.getPrivate());
//    att.constructAttestation(request, response, signature, userKeys.getPublic());
  }

  public static AsymmetricCipherKeyPair constructKeys(SecureRandom rand) {
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(DOMAIN, rand);
    generator.init(keygenParams);
    return generator.generateKeyPair();
  }
}