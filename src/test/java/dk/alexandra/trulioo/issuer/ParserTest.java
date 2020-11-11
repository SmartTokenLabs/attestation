package dk.alexandra.trulioo.issuer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ParserTest {

  @Test
  public void testSunshine() throws Exception {
    String request = Files.readString(Path.of("src/test/data/verification_request.json"));
    String response = Files.readString(Path.of("src/test/data/verification_response.json"));
    Parser parser = new Parser(new JSONObject(request), (new JSONObject(response)).getJSONObject("Record"));
    Map<String, X500Name> names = parser.getX500Names();
    Map<String, Extensions> extensions = parser.getExtensions();

    Assertions.assertEquals(names.size(), 2);
    Assertions.assertEquals(extensions.size(), 2);
    Assertions.assertTrue(names.containsKey("National Change of Address"));
    Assertions.assertTrue(names.containsKey("NZ Driver Licence"));
    Assertions.assertTrue(extensions.containsKey("National Change of Address"));
    Assertions.assertTrue(extensions.containsKey("NZ Driver Licence"));
    Set<String> expectedNameFields =
        new HashSet<String>(Arrays.asList(Parser.OID_COUNTRY_NAME, Parser.OID_GIVEN_NAME, Parser.OID_SUR_NAME, Parser.OID_STATE_OR_PROVINCE_NAME));
    for(X500Name name: names.values()) {
      Set<String> oids = Arrays.stream(name.getAttributeTypes()).map(c -> c.toString()).collect(Collectors.toSet());
      Assertions.assertEquals(oids.size(), expectedNameFields.size());
      Assertions.assertEquals(oids, expectedNameFields);
      Set<String> encs = Arrays.stream(name.getRDNs()).map(
          c -> c.getTypesAndValues()[0].getValue().toString()).collect(
          Collectors.toSet());
      Assertions.assertEquals(encs.size(), 4);
      Assertions.assertTrue(encs.contains("NZ"));
      Assertions.assertTrue(encs.contains("JaneKone"));
      Assertions.assertTrue(encs.contains("Doe"));
      Assertions.assertTrue(encs.contains("Queensland"));
    }
    Set<String> expectedDLExtensions = new HashSet<>(Arrays.asList(Parser.OID_STREET_ADDRESS, Parser.OID_SUBURB, Parser.OID_POSTAL_CODE, Parser.OID_DATE_OF_BIRTH));
    Set<String> oids = Arrays.stream(extensions.get("NZ Driver Licence").getExtensionOIDs()).map(c -> c.toString()).collect(
          Collectors.toSet());
    Assertions.assertEquals(expectedDLExtensions.size(), oids.size());
    Assertions.assertEquals(expectedDLExtensions, oids);
    Set<String> encs = Arrays.stream(extensions.get("NZ Driver Licence").getExtensionOIDs()).map(c -> new String(extensions.get("NZ Driver Licence").getExtension(c).getExtnValue().getOctets())).collect(
        Collectors.toSet());
    Assertions.assertEquals(encs.size(), 4);
    Assertions.assertTrue(encs.contains("1973111100"));
    Assertions.assertTrue(encs.contains("13 Markeri Street"));
    Assertions.assertTrue(encs.contains("4218"));
    Assertions.assertTrue(encs.contains("Mermaid Beach"));

    Set<String> expectedCAExtensions = new HashSet<>(Arrays.asList(Parser.OID_STREET_ADDRESS, Parser.OID_SUBURB, Parser.OID_POSTAL_CODE));
    Set<String> caOids = Arrays.stream(extensions.get("National Change of Address").getExtensionOIDs()).map(c -> c.toString()).collect(
        Collectors.toSet());
    Assertions.assertEquals(expectedCAExtensions.size(), caOids.size());
    Assertions.assertEquals(expectedCAExtensions, caOids);
    Set<String> caEncs = Arrays.stream(extensions.get("National Change of Address").getExtensionOIDs()).map(c -> new String(extensions.get("National Change of Address").getExtension(c).getExtnValue().getOctets())).collect(
        Collectors.toSet());
    Assertions.assertEquals(caEncs.size(), 3);
    Assertions.assertTrue(caEncs.contains("13 Markeri Street"));
    Assertions.assertTrue(caEncs.contains("4218"));
    Assertions.assertTrue(caEncs.contains("Mermaid Beach"));

  }
}
