Steps to send MagicLinks:

1.  a) Put existing _key.pem_ to the _./keys_ folder 
    or
    b) run _keys/create_key.sh_ - it will generate new _key.pem_(private secret Issuer key) and _public.pem_ (to share with other parties to validate signature)

2.  create file _data/ticketReceivers.txt_ with emails list , one per line.

3.  set Outlet domain name. Its Landing page, where MagicLinks point to. You can set in in the _index.js_

```
let outletPath = "https://some_domain";
let fileWithEmails = 'data/ticketReceivers.txt'; // in this valiable you can change file name from _ticketReceivers.txt_ to some another name
```

4.  set variables to the _.env_ file. Required to send emails through SMTP server.

```
SMTP_USERNAME   = email
SMTP_PASS       = pass
SMTP_PORT       = 465
SMTP_SERVER     = url
```

5.  https://github.com/TokenScript/attestation/tree/generator/generator - check manual and build attestation-0.3.17-all.jar file and copy it to this folder, becaue script will use it to generate MagicLink

6.  run ```node index.js```, it will parse ticketReceivers.txt and create new file data/parsed.json with list of parsed emails and send result and MagicLinks included to the user emails.

