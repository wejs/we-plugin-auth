const lt = {
  // Clean up people that have given up
  resetTime: 600000, // 10 min
  verifyTime: 600000, // 10 min

  failures: {},

  canLogin(req) {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    const f = this.failures[ip];
    if (f && Date.now() < f.nextTry && f.count > 3) {
      // Throttled. Can't try yet.
      return false;
    }

    return true;
  },

  onLoginFail(req) {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (!this.failures[ip]) {
      this.failures[ip] = {
        count: 0,
        nextTry: new Date()
      };
    }

    const f = this.failures[ip];

    // Wait another two seconds for every failed attempt
    ++f.count;
    f.nextTry.setTime(Date.now() + 2000 * f.count);
  },

  onLoginSuccess(req) {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    delete this.failures[ip];
  }
};

setInterval(function() {
  for (let ip in lt.failures) {
    if (Date.now() - lt.failures[ip].nextTry > lt.resetTime) {
      delete lt.failures[ip];
    }
  }
}, lt.verifyTime);

module.exports = lt;