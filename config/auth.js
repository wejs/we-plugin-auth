module.exports.auth = {
  isProvider: false,
  isConsumer: true,

  cookieDomain: '.cdp.dev',
  cookieName: 'cdp',
  cookieMaxAge: 900000,
  cookieSecure: false,

  honeypot: {
    // add a honeypot key to enable this feature
    key: null,
    maxThreatScore: 80,
    // enable honeypot check in tests?
    checkInTests: false
  }
}
