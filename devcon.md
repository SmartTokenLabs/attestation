# Constructing a Magic Link Ticket

## Outline

This document outlines how to construct Magic Link tickets for Devcon using the commandline. 
The ticket contains a reference to the relevant DevCon conference, as a string, a unique ticket ID, as an integer, an integer representing the class of the ticket.
The ticket furthermore contains a Pedersen commitment to an email address of the user who the ticket is issued towards. The hiding aspect of the commitment is based on a high entropy secret. 
Finally, the ticket is signed using ECDSA.

The format of a Magic Link is as follows:

    ?ticket=<ticket>&pok=<proof>&secret=<secret>&mail=<mail>

- `ticket` is the URL base64 encoded ticket. This can be made public and does NOT leak the user's email, only the conferenceID, unique ticket ID and ticket class.
- `pok` is a SOMEWHAT PRIVATE proof, URL base64 encoded, linking a cryptographic part of the ticket to its owner's email. NOTE: This needs to be kept somewhat private, since this together with the public ticket can allow an adversary to brute force the ticket owner's email. Thus, this value should NEVER be posted to the blockchain and only sent to trusted webservers.  
- `secret` is the PRIVATE high entropy secret that *only* the user receiving the ticket should learn. If it is made public, then it is possible, using brute force, to use the public ticket to check if it is issued towards a specific email.
- `mail` is the email of the user the ticket is issued towards.

An example of a Magic Link is as follows:

    ?ticket=MIGYMA8MATYCBwCMryzpzeQCAQAEQQQtqLOcLgwsajj19K141ER4A4fblUH-cH0ZM_HZQmylYiSxsPljEL--ldyfbPIslT7djTuYJakQdyapeuPpnEDjA0IA1LMfG8yWPpa2Yuyssn5fBB4MsNY3PpF0hwELzugBxw96zU4Q2k9jz5_L3Y3qIyshm8AH5EiIwm5k5LIZs3idghw=&pok=MIGqBEEECwGwPNcyCsaGTbr5_BVaThbVuQr7kUWGFI3XgT68kpMi3JGIuO5SCAX4C-ySQxSnQO-9qAZeUjYo7dfnyJiAuwQgLY3YogvmiVW8frt3wxbX9qIBqkgMTcoCdN8af7_QXCEEQQQWPq3mXaFk68AgZgOXq0ORy1XPeTicyazBHv7WGDa_3x-swwhLDW1q8JvvRfbi2t0juMdiEhiG4NgRF-4oOiIOBAA=&secret=2500912778337066279234681248258306901458202560990335799908059446412793265040&mail=some%40mail.dk


## Using demo jar file

After building the project (see [the readme](README.md)), you can use the executable jar from  

    build/libs/attestation-<version number>-all.jar

### Construct ticket

To construct a Magic Link ticket the necessary information to be contained in the ticket must be supplied via the commandline.
As a result the Magic Link will be printed on commandline.

Specifically the syntax of the command is as follows:

    java -cp attestation-<version number>-all.jar org.devcon.ticket.Issuer <private-key-name> <mail> <conferenceID> <ticketID> <ticket class>

- `private-key-name` is the path to the private key, which MUST be an elliptic curve key of RFC 5915 format, e.g. `priv.pem`.
- `mail` is the email of the user which the ticket should be issued towards, e.g. `some@mail.dk`.
- `conferenceID` is the string representing the ID of the DevCon conference where the ticket is valid, e.g. `bogota21`.
- `ticketID` is the unique integer ticket ID, e.g. `1234567890`.
- `ticket class` is an integer representing the class of the issued ticket.

For example:

     java -cp attestation-<version number>-all.jar org.devcon.ticket.Issuer priv.pem some@mail.com bogota21 1234567890 1

### Validate ticket

To validate a ticket, the URL encoding of the ticket, along with an associated URL-encoded proof, linking the ticket to an email, is needed. 

Specifically the syntax of the command is as follows:

    java -cp attestation-<version number>-all.jar org.devcon.ticket.Validator <public-key-name> <ticket> <pok> <mail>

- `public-key-name` is the path to the public key, which MUST be an elliptic curve key, e.g. `pub.pem`.
- `ticket` is the URL base64 encoded ticket. 
- `pok` is a SOMEWHAT PRIVATE proof, URL base64 encoded, linking a cryptographic part of the ticket to its owner's email. 
- `mail` is the email of the user which the ticket has been issued towards, e.g. `some@mail.dk`.

The command will print `Ticket is VALID and was issued to email some@mail.dk` if the ticket is valid, otherwise it will return an error.

For example:

    java -cp attestation-0.3.16-all.jar org.devcon.ticket.Validator pub.pem MIGYMA8MATYCBwCMryzpzeQCAQAEQQQtqLOcLgwsajj19K141ER4A4fblUH-cH0ZM_HZQmylYiSxsPljEL--ldyfbPIslT7djTuYJakQdyapeuPpnEDjA0IA1LMfG8yWPpa2Yuyssn5fBB4MsNY3PpF0hwELzugBxw96zU4Q2k9jz5_L3Y3qIyshm8AH5EiIwm5k5LIZs3idghw= MIGqBEEECwGwPNcyCsaGTbr5_BVaThbVuQr7kUWGFI3XgT68kpMi3JGIuO5SCAX4C-ySQxSnQO-9qAZeUjYo7dfnyJiAuwQgLY3YogvmiVW8frt3wxbX9qIBqkgMTcoCdN8af7_QXCEEQQQWPq3mXaFk68AgZgOXq0ORy1XPeTicyazBHv7WGDa_3x-swwhLDW1q8JvvRfbi2t0juMdiEhiG4NgRF-4oOiIOBAA= some@mail.dk
