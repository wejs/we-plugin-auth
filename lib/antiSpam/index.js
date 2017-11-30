const request = require('request');

module.exports = {
  recaptcha: {
    /**
     * Get recaptcha secret and key with support to systemSettigns and local settings
     *
     * @param  {Object} req   Express request
     * @return {Object|null}  Object with {secret,key} or null
     */
    getConfiguration(req) {
      const we = req.we;
      const _ = we.utils._;

      let cfgs = {
        secret: null,
        key: null
      };

      // first check if recaptcha cfgs is set with systemSettings:
      if (we.systemSettings) {
        cfgs.secret = we.systemSettings.recaptchaSecret;
        cfgs.key = we.systemSettings.recaptchaKey;

        if (cfgs.secret && cfgs.key) {
          return cfgs; // configs set with systemSettings
        }
      }

      // default for static recaptcha configs:
      cfgs.secret = _.get(we, 'config.apiKeys.recaptcha.secret');
      cfgs.key = _.get(we, 'config.apiKeys.recaptcha.key');

      if (cfgs.secret && cfgs.key) {
        return cfgs; // configs set with static configs
      }

      // secret and key configurations not found:
      return null;
    },
    /**
     * Verify the Recaptcha response.
     *
     * returns false for not spam and true for spam
     *
     * @param {Function} callback
     * @api public
     */
    verify(req, res, callback) {
      const cfgs = this.getConfiguration(req);

      // skip if configs not found:
      if (!cfgs) {
        req.we.log.verbose('we.antiSpam.recaptcha: not configured, skiped');
        return callback(null, false);
      }

      let ip = ( req.headers['x-forwarded-for'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress );

      request.post('https://www.google.com/recaptcha/api/siteverify', {
          form: {
            secret: cfgs.secret,
            response: req.body['g-recaptcha-response'],
            remoteip: ip,
          }
        }, (error, response, body)=> {
          // success
          if (!error && body)  {
            try {
              const r = JSON.parse(body);
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