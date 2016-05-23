var request = require('request');

module.exports = {
  recaptcha: {
    /**
     * Verify the Recaptcha response.
     *
     * returns false for not spam and true for spam
     *
     * @param {Function} callback
     * @api public
     */
    verify: function verify(req, res, callback) {
      // skip if is disabled
      if (!req.we.config.apiKeys.recaptcha.secret) {
        req.we.log.verbose('we.antiSpam.recaptcha: not configured, skiped');
        return callback(null, false);
      }

      var ip = req.headers['x-forwarded-for'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress;

      request.post('https://www.google.com/recaptcha/api/siteverify', {
          form: {
            secret: req.we.config.apiKeys.recaptcha.secret,
            response: req.body['g-recaptcha-response'],
            remoteip: ip,
          }
        }, function (error, response, body) {
          // success
          if (!error && body)  {
            try {
              var r = JSON.parse(body);
              if (r.success) {
                return callback(null, false);
              }
            } catch(e) {
              return callback(e, true);
            }
          }
          // is spam
          callback(error, true, response);
        }
      );
    }
  }
}