let tokenMock = [
  { token: { ticketId: 42, ticketClass: "VIP", conferenceId: 1 }, ownerAddress: null },
  { token: { ticketId: 32, ticketClass: "STANDARD", conferenceId: 1 }, ownerAddress: 2 },
  { token: { ticketId: 15, ticketClass: "VIP", conferenceId: 1 }, ownerAddress: 2 },
];

const Negociator = {
  init: () => {
    return "Hello Negociator";
  },
  getTokenInstances: function async() {
    return tokenMock
  }
}

export {
  Negociator
};