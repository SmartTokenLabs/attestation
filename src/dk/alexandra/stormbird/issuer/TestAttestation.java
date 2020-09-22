package dk.alexandra.stormbird.issuer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi.EC;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import sun.security.x509.X509CertImpl;

public class TestAttestation {
  public static final ECDomainParameters DOMAIN = new ECDomainParameters(Attestation.CURVE_PARAM.getCurve(), Attestation.CURVE_PARAM.getG(), Attestation.CURVE_PARAM.getN(), Attestation.CURVE_PARAM.getH());
  private static AsymmetricCipherKeyPair serverKeys, userKeys;
  private static String request, response;
  private static SecureRandom rand;

  @org.junit.BeforeClass
  public static void setupKeys() throws Exception {
    rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    serverKeys = constructSecp256k1Keys(rand);
    userKeys = constructSecp256k1Keys(rand);
    request = Files.readString(Path.of("tests/verification_request.json"));
    response = Files.readString(Path.of("tests/verification_response.json"));
  }

  @Test
  public void testSunshine() throws Exception {
    Attestation att = new Attestation(serverKeys);
    byte[] requestJson = request.getBytes(StandardCharsets.UTF_8);
    byte[] signature = SignatureUtil.signKeccak(requestJson, userKeys.getPrivate());
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(userKeys.getPublic());
    byte[] userPK = spki.getPublicKeyData().getEncoded();
    List<byte[]> certs = att.constructAttestation(request, response, signature, userPK);
//    JcaX509ContentVerifierProviderBuilder builder = new JcaX509ContentVerifierProviderBuilder();
//    SubjectPublicKeyInfo issuerSpki =  SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(serverKeys.getPublic());
//    issuerSpki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(OID_SIGNATURE_ALG)),  // ECDSA with SHA256 which is needed for a proper x509
//        issuerSpki.getPublicKeyData());
//    ContentVerifierProvider verifier = builder.build(issuerSpki);
//    for (byte[] current : certs) {
//      X509CertificateHolder currentCert = new X509CertificateHolder(current);
//      Assert.assertTrue(currentCert.isValidOn(new Date(System.currentTimeMillis())));
//      Assert.assertTrue(currentCert.isSignatureValid(verifier));
//    }
    PublicKey serverPK = new EC().generatePublic(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(serverKeys.getPublic()));
    for (byte[] current : certs) {
      X509Certificate cert = new X509CertImpl(current);
      try {
        cert.verify(serverPK, new BouncyCastleProvider());
        cert.checkValidity();
      } catch (CertificateExpiredException | CertificateNotYetValidException e) {
        Assert.fail();
      }
    }

  }

  public static AsymmetricCipherKeyPair constructSecp256k1Keys(SecureRandom rand) {
    ECKeyPairGenerator generator = new ECKeyPairGenerator();
    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(DOMAIN, rand);
    generator.init(keygenParams);
    return generator.generateKeyPair();
  }

//  public static AsymmetricCipherKeyPair constructStandardKeys(SecureRandom rand) {
//    ECKeyPairGenerator generator = new ECKeyPairGenerator();
//    ECNamedDomainParameters n = new ECNamedDomainParameters(new ASN1ObjectIdentifier(
//        Attestation.OID_SIGNATURE_ALG), DOMAIN);
//    ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(n, rand);
//    generator.init(keygenParams);
//    return generator.generateKeyPair();
//  }
}