"use strict";
const nodemailer = require("nodemailer");
const QRCode = require('qrcode')

const fs = require('fs').promises;

require('dotenv').config();

let publicKeyFile = "keys/public.pem";
let QRReceiverEmail = "oleg.grib.ua@gmail.com"

function validateENV(){
  if (
    !process.env.SMTP_SERVER  
    || !process.env.SMTP_PORT  
    || !process.env.SMTP_USERNAME  
    || !process.env.SMTP_PASS  
    ){
    console.log(".env valiables required: SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASS");
    return false;
  }
  return true;
}

let transporter = nodemailer.createTransport({
  host: process.env.SMTP_SERVER,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_USERNAME,
    pass: process.env.SMTP_PASS
  }
}) 



async function sendEmail(){

    let key;
    try {
        key = await fs.readFile(publicKeyFile, "utf8");
    } catch(e){
        console.error(e)
        return
    }

    let qr = "";
    try {
        qr =  await QRCode.toDataURL(key);
    } catch(e){
        console.error(e)
        return
    }

    try {
        // prepare data to send
        let inputData = {
        from: 'anna@antopolbus.rv.ua', // sender address
        to: QRReceiverEmail, // list of receivers
        subject: "AttestatonDAO PublicKey as QR", // Subject line
        text: "This is Public Key in PEM format:\n'" + key + "'", // plain text body
        html: `This is Public Key in PEM format:<br><pre>${key}</pre><br> And in QR code format for AttestationDAO App.<img src="cid:publicKey@smarttokenlabs.com"/>`, // html body
        }

        if (qr) {
        inputData.attachments = [{
            filename: 'publicKey.png',
            path: qr,
            cid: 'publicKey@smarttokenlabs.com' //same cid value as in the html img src
        }]
        }

        // send mail with defined transport object
        let info = await transporter.sendMail(inputData);

        if (info.messageId) {
            console.log(`Email sent. messageid: ${info.messageId}`);
        } else {
            console.log(e);
            console.log(`Cant send email.`);
        }

    } catch(e){
        console.log(e);
        console.log(`Cant send email.`);
    }

}

// async..await is not allowed in global scope, must use a wrapper
async function main() {
    // .env vars required to send emails
    if (!validateENV()){
        return;
    }

    await sendEmail();

}

main().catch(console.error);