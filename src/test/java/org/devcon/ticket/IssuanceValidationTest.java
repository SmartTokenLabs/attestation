package org.devcon.ticket;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class IssuanceValidationTest {
  private static final String MAIL = "test@test.ts";
  private static final BigInteger TICKET_ID = new BigInteger("48646");
  private static final int TICKET_CLASS = 0; // Regular ticket
  private static final String CONFERENCE_ID = "6.Ø"; // Ensure it can handle utf8


  // Courtesy of stackoverflow  https://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
  public static Map<String, String> splitQuery(String query) throws UnsupportedEncodingException {
    query = query.substring(1); // Remove ?
    Map<String, String> query_pairs = new LinkedHashMap<String, String>();
    String[] pairs = query.split("&");
    for (String pair : pairs) {
      int idx = pair.indexOf("=");
      query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
    }
    return query_pairs;
  }

  @Test
  public void sunshine() {
    // Unnamed curve
    try {
      String output = Issuer.constructTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
          Path.of("src/test/data/ecPrivKey.pem"));
      Map<String, String> parameters = splitQuery(output);
      Validator.validateTicket(parameters.get("ticket"), parameters.get("pok"),
          parameters.get("mail"), Path.of("src/test/data/ecPubKey.pem"));
    } catch (Exception e) {
      fail();
    }
  }

  @Test
  public void sunshineNamed() {
    // Named curve
    try {
      String output = Issuer.constructTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
          Path.of("src/test/data/namedEcPrivKey.pem"));
      Map<String, String> parameters = splitQuery(output);
      Validator.validateTicket(parameters.get("ticket"), parameters.get("pok"),
          parameters.get("mail"), Path.of("src/test/data/namedEcPubKey.pem"));
    } catch (Exception e) {
      fail();
    }
  }

  @Test
  public void worksWithNonLatinLettees() {
    // Unnamed curve
    try {
      String output = Issuer.constructTicket("æ_mæget@dansk.mail", CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
          Path.of("src/test/data/ecPrivKey.pem"));
      Map<String, String> parameters = splitQuery(output);
      Validator.validateTicket(parameters.get("ticket"), parameters.get("pok"),
          parameters.get("mail"), Path.of("src/test/data/ecPubKey.pem"));
    } catch (Exception e) {
      fail();
    }
  }


  @Test
  public void wrongMail() throws Exception {
    String output = Issuer.constructTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
        Path.of("src/test/data/ecPrivKey.pem"));
    Map<String, String> parameters = splitQuery(output);
    assertThrows( RuntimeException.class, () -> Validator.validateTicket(parameters.get("ticket"), parameters.get("pok"),
        "not@right.mail", Path.of("src/test/data/ecPubKey.pem")));
  }

  @Test
  public void wrongKey() throws Exception {
    String output = Issuer.constructTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
        Path.of("src/test/data/ecPrivKey.pem"));
    Map<String, String> parameters = splitQuery(output);
    assertThrows( RuntimeException.class, () -> Validator.validateTicket(parameters.get("ticket"), parameters.get("pok"),
        "not@right.mail", Path.of("src/test/data/namedEcPubKey.pem"))); // Wrong public key
  }

  @Test
  public void wrongPok() throws Exception {
    String output = Issuer.constructTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
        Path.of("src/test/data/ecPrivKey.pem"));
    Map<String, String> parameters = splitQuery(output);
    String otherOutput = Issuer.constructTicket("other@mail.dk", CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
        Path.of("src/test/data/ecPrivKey.pem"));
    Map<String, String> otherParameters = splitQuery(otherOutput);

    // Using PoK from the other ticket
    assertThrows( RuntimeException.class, () -> Validator.validateTicket(parameters.get("ticket"), otherParameters.get("pok"),
        parameters.get("mail"), Path.of("src/test/data/ecPubKey.pem")));
  }

  @Test
  public void cannotCombineTickets() throws Exception {
    String output = Issuer.constructTicket(MAIL, CONFERENCE_ID, TICKET_ID, TICKET_CLASS,
        Path.of("src/test/data/ecPrivKey.pem"));
    Map<String, String> parameters = splitQuery(output);
    String otherOutput = Issuer.constructTicket("other@mail.dk", CONFERENCE_ID, TICKET_ID,
        TICKET_CLASS,
        Path.of("src/test/data/ecPrivKey.pem"));
    Map<String, String> otherParameters = splitQuery(otherOutput);

    // Using PoK and email from other ticket
    assertThrows(RuntimeException.class,
        () -> Validator.validateTicket(parameters.get("ticket"), otherParameters.get("pok"),
            otherParameters.get("mail"), Path.of("src/test/data/ecPubKey.pem")));
  }
}
