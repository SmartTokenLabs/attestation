"use strict";
const nodemailer = require("nodemailer");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);

const fs = require('fs').promises;

require('dotenv').config();

let outletPath = "https://some_domain";
let fileWithEmails = 'data/ticketReceivers.txt';
let fileWithParsedData = 'data/parsed.json';

const TICKET_CONFERENCE = "AttestationDAO";
const TICKET_CLASS = 0;

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

const emailRegexp = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;


async function createMagicLink(email, ticketId, conferenceID, ticketClass) {

  let request = `java -cp ./attestation-0.3.17-all.jar org.devcon.ticket.Issuer keys/key.pem "${email}" ${conferenceID} ${ticketId} ${ticketClass} | grep -v "org.tokenscript.attestation.core.SignatureUtility"  2>/dev/null`;
  const nameOutput = await exec(request);
  
  // Exec output contains both stderr and stdout outputs
  return nameOutput.stdout.trim();
}

async function readEmailsFromFile(){
  try {
    const data = await fs.readFile(fileWithEmails, "utf8");

    var emails = data.split("\n").map(i => i.trim()).filter(i => i != "");

    return emails;

  } catch(e){
    console.error(e)
    return
  }
  
}

async function sendEmail(item){

  try {
    // prepare data to send
    let inputData = {
      from: 'anna@antopolbus.rv.ua', // sender address
      to: item.email, // list of receivers
      subject: "AttestatonDAO MagicLink", // Subject line
      text: outletPath + item.magicLink, // plain text body
      html: `<a href="${outletPath + item.magicLink}">Click this MagicLink to save it in the browser</a>`, // html body
    }

    // send mail with defined transport object
    let info = await transporter.sendMail(inputData);

    if (info.messageId) {
      // messageId example <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
      item.sent = info.messageId;
    } else {
      console.log(`Cant send email to the "${item.email}", skipping.`);
    }

  } catch(e){
    console.log(`Cant send email to the "${item.email}", skipping.`);
  }

  return item;

}

async function saveParsed(data){
    fs.writeFile(fileWithParsedData, JSON.stringify(data));
}

// async..await is not allowed in global scope, must use a wrapper
async function main() {

  let allData = [];
  try {
    let rawdata = await fs.readFile(fileWithParsedData);
    allData = JSON.parse(rawdata);
    console.log(`${allData.length} items found in the "${fileWithParsedData}"`);
  } catch(e){
    console.log("Looks like no parsed data saved. Lets try to read rew emails.");
  }

  let ticketId = allData.length;
  let badEmails = [];

  let rawEmails = await readEmailsFromFile();

  if (rawEmails.length) {
    console.log(`${rawEmails.length} lines found in the "${fileWithEmails}"`);
    rawEmails.map(email=>{
      
      // we are going to send MagicLinks to the emails, so have to validate emails format
      if(emailRegexp.test(email)){
        ticketId++;
        allData.push({
          ticketId,
          email,
          magicLink: "",
          sent: false
        })
      } else {
        // will save rest of lines back to the file
        badEmails.push(email);
      }
      
    })

    console.log(`${allData.length} total items in the new "${fileWithParsedData}"`);

    // save data to JSON and remove raw file
    await saveParsed(allData);
    // save wrong emails back to the file
    fs.writeFile(fileWithEmails    , badEmails.join("\n"));
    // fs.rm(fileWithEmails);
    
  } else {
    if (!allData.length) {
      console.log("Nothing to do there. Exit.");
      return;
    } else {
      console.log(`Empty file: ${fileWithEmails}, lets check other items... `);
    }
  }

  try {
    await fs.readFile("keys/key.pem");
    console.log(`keys/key.pem found.`);
  } catch(e){
    console.log("keys/key.pem key required to generate MagicLinks, please check README.md, exit.");
    return;
  }

  try {
    // fill all emails with magicLinks 
    let newMagicLinksNumber = 0;
    allData = await Promise.all(allData.map(async function(item) {
      if (!item.magicLink){
        let magicLink = await createMagicLink(item.email, item.ticketId, TICKET_CONFERENCE, TICKET_CLASS );
        item.magicLink = magicLink;
        newMagicLinksNumber++;
      }
      return item;
    }))

    console.log(`${newMagicLinksNumber} new Magic Links generated`);

    // save data with attestations
    await saveParsed(allData);

  } catch(e){
    console.log("Something went wrong with attestation...");
    console.log(e);
  }

  // .env vars required to send emails
  if (!validateENV()){
    return;
  }

  let newEmailsSent = 0;
  for (let i = 0; i < allData.length; i++) {
    // dont send email again
    if (allData[i].sent) continue;

    // send if failed privously
    let updated = await sendEmail(allData[i]);
    allData[i] = updated;
    newEmailsSent++;
    await saveParsed(allData);
  }

  console.log(`${newEmailsSent} new Magic Links sent to customer emails`);

}

main().catch(console.error);