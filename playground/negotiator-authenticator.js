
// onload :
async function() {
    const tokens = (await Negotiator.getXXXTokenInstances());
    tokens.forEach(putTokenOnUI);

    // getting the attributes of tokens

    isVIP = false;
    tokens.forEach(
        ticket => {
            if (token.ticketClass == "VIP") isVIP = true;
        }
    }

    // isVIP == the user has at least one token which is VIP.

    document.getElementByID("vip-only-section").style.visibility = "visible";
}()

// when user clicked "VIP room" button

async function vip-room-clicked() {
    
    /// ... let user choose which ticket to use for authentication
    vip-tickets = tokens.filter( ticket => (ticket.ticketClass== "VIP") );

    // populate the vip-ticket selector window
    populate-vip-ticket(vip-tickets).then(chosenTicket => {
        // first approach: disney mode
        // this will lead to sign-message or email code
        Authenticator.authenticate(chosenTicket).then(success, failure);
    });

    // non-disney mode
    populate-vip-ticket(vip-tickets).then(chosenTicket => {
        if (chosenTicket.ownerAddress == null ) {
            Authenticator.findOwner() // lead to email code modal process, created by Authenticator.
        }
        if (chosenTicket.ownerAddress == currentUser.ownerAddress) {
            // this will lead to sign-message, even if user typed the code in email.
            Authenticator.authenticateAddress(currentUser.ownerAddress).then(success, failure);
        }
    });
}

// if the website generates a transaction to a smart contract which
// requires a valid ticket.

async function voteButtonCicked(ticket) {
    // generate the vote transaction payloads (e.g. whom voted)
    const payload = {vote: votedGui, weight: 3, expiry: 98109802843804}
    payload.push(Authenticator.getProofOf(ticket))
    // now it is {vote: votedGui, weight: 3, expiry: 98109802843804, ticketProof: proof}
    // where the genreation of the proof might involve receiving email code in modal.
    tx = {nounce: nounce, ......, payload: payload}
    web3.ethereum.sendTransaction(tx); // then track the transaction status ...
}

// card at work: this will use wallet if possible, and this only works
// if the vote action is provided (by the issuer)
async function voteButtonClick() {
    ticket.actions["vote"].render(document.querySelector(".voteCardContainer")).then(tx => watch(tx));
}
