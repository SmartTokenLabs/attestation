# Constructing a Magic Link Ticket

## Outline

This document outlines how to construct Magic Link tickets for Devcon using the commandline. 
The ticket contains a reference to the relevant DevCon conference, as a string, a unique ticket ID, as an integer, an integer representing the class of the ticket.
The ticket furthermore contains a Pedersen commitment to an email address of the user who the ticket is issued towards. The hiding aspect of the commitment is based on a high entropy secret. 
Finally, the ticket is signed using ECDSA.

An example of a Magic Link is as follows:

    ?ticket=MIGcMBMMCGJvZ290YTIxAgRJlgLSAgEBBEEEEIbQ7qlmn0BqBOTcRw95C6wlaaLg6cMQ3fFLHFx5Qk8e77yHMISrAd4adMw1aqbVeAQ3iDfZdMrSoWoLnTHGLANCALWCu66ayo8VVo-95UWtIsgHGpfxXzu0L0ZRroGw7z5oJzxBDm9rcF1AR-elMliZkcSwySA_gFTiF8Wq89LWF64b&secret=21033356303350810820379799995918750445469937420755277029181164058960176667547&mail=some@mail.com

- `ticket` is the base64 encoded ticket. This can be made public and does NOT leak the user's email, only the conferenceID, unique ticket ID and ticket class. 
- `secret` is the PRIVATE high entropy secret that *only* the user receiving the ticket should learn. If it is made public, then it is possible, using brute force, to use the public ticket to check if it is issued towards a specific email. 
- `mail` is the email of the user the ticket is issued towards. 

## Using demo jar file

After building the project (see [the readme](README.md)), you can use the executable jar from  

    build/libs/attestation-all.jar

### Construct ticket

To construct a Magic Link ticket the necessary information to be contained in the ticket must be supplied via the commandline.
As a result the Magic Link will be printed on commandline.

Specifically the syntax of the command is as follows:

    java -cp attestation-all.jar org.devcon.ticket.Issuer <private-key-name> <mail> <conferenceID> <ticketID> <ticket class>

- `private-key-name` is the path to the private key, which MUST be an elliptic curve key of RFC 5915 format, e.g. `priv.pem`.
- `mail` is the email of the user which the ticket should be issued towards, e.g. `some@mail.com`.
- `conferenceID` is the string representing the ID of the DevCon conference where the ticket is valid, e.g. `bogota21`.
- `ticketID` is the unique integer ticket ID, e.g. `1234567890`.
- `ticket class` is an integer representing the class of the issued ticket.

For example:

     java -cp attestation-all.jar org.devcon.ticket.Issuer priv.pem some@mail.com bogota21 1234567890 1

    java -cp attestation-0.3.10-all.jar org.devcon.ticket.Validator pub.pem MIGYMA8MATYCBwCMryzpzeQCAQAEQQQtqLOcLgwsajj19K141ER4A4fblUH-cH0ZM_HZQmylYiSxsPljEL--ldyfbPIslT7djTuYJakQdyapeuPpnEDjA0IA1LMfG8yWPpa2Yuyssn5fBB4MsNY3PpF0hwELzugBxw96zU4Q2k9jz5_L3Y3qIyshm8AH5EiIwm5k5LIZs3idghw= MIGqBEEECwGwPNcyCsaGTbr5_BVaThbVuQr7kUWGFI3XgT68kpMi3JGIuO5SCAX4C-ySQxSnQO-9qAZeUjYo7dfnyJiAuwQgLY3YogvmiVW8frt3wxbX9qIBqkgMTcoCdN8af7_QXCEEQQQWPq3mXaFk68AgZgOXq0ORy1XPeTicyazBHv7WGDa_3x-swwhLDW1q8JvvRfbi2t0juMdiEhiG4NgRF-4oOiIOBAA= some@mail.dk
