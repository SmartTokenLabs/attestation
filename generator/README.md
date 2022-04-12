# MagicLink Generator Flow

## Prebuild task

check file pemission for scripts (should be 755):
*./build_jar.sh*
*./create_key.sh*
*./create_magic_link.sh*

## Build Attestation.jar

**Commands included to the script** 
*./build_jar.sh*

## If you already have ready Private and Public keys then please skip this step and put private key file to this folder

Generate privateKey to sign Tickets or skip this step if you have privateKey already 

```openssl ecparam -name secp256k1 -genkey -noout -out key.pem```

this will produce keyfile with content like:

```
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIEcuGnwFuPM6p2C4AagkLv4k4rVse6xyZGCcr2+fN1xgoAcGBSuBBAAK
oUQDQgAE8rH51kExgjGZI6N6Lug9ZUn73FO+O1Jr436Fksr0HiPvq4/QGuOZ9tvr
4RCvnUCC68OO3xqeX7jsKQJkHmSNew==
-----END EC PRIVATE KEY-----
```

```openssl ec -in key.pem -pubout -out public.pem```

This command create publicKey of MagicLink issuer. This key requred for third-party apps to ensure that ticket is generated and signed with correct key

**Commands included to the script** 
*./create_key.sh*

## Generate MagicLink with embedded ticket

Fields: 
__email@email.com__ - replace with user email (in case if project require email attestation then attestaed email must fit this email)
__param1(confirenceID)__ - (string) unique conference ID ( 6, 26 already used)
__param2(tcketID)__ - (string) unuque per event Ticket ID
__param3(tcketClass)__ - (number) for future use 

```java -cp ./attestation-0.3.17-all.jar org.devcon.ticket.Issuer ./key.pem email@email.com param1(confirenceID) param2(tcketID) param3(tcketClass)```

this will generate MagicLink in the format:

```
?ticket=MIGTME0MAjExAgEWAgEhBEEEIdSe96Wwg7cPror4Euq5s8l65IeaLr6GdRx20T6a7dkKFbPDvRPEIe0D_b4b5jLJ00xJmhis7c40T_CY0ZzNmwNCAKslx7MUwPvDjMYQFYAwurfS7kXEuvAStubglDIBpxNQWKOPQI4Yf2CyqAQkNvYkVtz_Q1WZom3eZhtsgtPZsWwc&pok=MIGqBEEEBZ49mGPoMDtog2n4ugwoSlLNqn4zk-c5bBKAkhjk2NUj8afyYmkMQjuNWQn9NBIP-5G6JCuO67u2aCVX0b5evgQgKK4tgC1TLAqNRDOVj0QUvl-33QG4SxaLNFw72Ze0DYYEQQQX7X_wtC5fqY08DIK1S4BnpaClx8j_yresWb3uAwp6FBwQ7TBxTACLj3j-qUsyj0P1RW_ugKgNsM7JQ3P5mJppBAA=&secret=6059438377138261600348796013275208287741621271881356523790135807560917097716&mail=email%40email.com
```

Need to prefix this line with outlet URI and send to the user email.

**Commands included to the script** 
*./create_magic_link.sh*
