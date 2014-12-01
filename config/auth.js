module.exports.auth = {
  isProvider: false,
  isConsumer: true,

  honeypot: {
    // add a honeypot key to enable this feature
    key: null,
    maxThreatScore: 80
  }
}
