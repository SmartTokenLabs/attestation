import { main, issue } from "../src/issue";

describe("Terminal Issuer", () => {
	let node = "";
	let script = "";
	let command = "issue";
	let network = "ethereum";
	let networkVersion = "0.26";
	let conferenceId = "event1";
	let privateKey =
		"6eadaac34974215df02079dbd71231fc0fd533566da263a67c9af7d86c7f0f7d";
	let ticketAttestationEmail = "email1@email.com";
	let tokenId = "1";
	let tokenClass = "0";
	let validityTo = "";
	let validityFrom = "";

    async function getInitObject(){
        let args = [
			node,
			script,
			command,
			network,
			networkVersion,
			conferenceId,
			privateKey,
			ticketAttestationEmail,
			tokenId,
			tokenClass,
		];
		return JSON.parse((await main(args)) || "{}");
    }

	it("issue", async () => {
		expect(await getInitObject()).toHaveProperty("success", true);
	});

    it("verify", async () => {
        
        let localCommand = "verify"
        
        let readyObject = await getInitObject()
        let params = (new URLSearchParams(readyObject['data'].substring(1)));

        let ticket = params.get("ticket") || "";
    
		let args = [
			node,
			script,
			localCommand,
			network,
			networkVersion,
			conferenceId,
			privateKey,
			ticket
		];
		readyObject = JSON.parse((await main(args)) || "{}");
        console.log(readyObject)
		expect(readyObject).toHaveProperty("success", true);
	});
});
