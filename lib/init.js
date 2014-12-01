var wePassport = require('we-passport');

module.exports = function initPlugin(sails, cb) {
  // initialize passport configs
  var passportMiddleware =  wePassport.init(sails);

  // on router:before event ...
  sails.on('router:before',function () {
    // bind passport hook
    sails.router.bind('/*', function (req, res, next) {
      passportMiddleware(req, res, next);
    });

    sails.emit('we:passport:bind:after', sails);
  });

  // Honeypot
  // Set honeypot on ready function
  // TODO mode to one sails.js module hook
  var honeypotKey = sails.config.auth.honeypot.key;
  if ( honeypotKey ) {
    sails.honeypot = require('project-honeypot')(honeypotKey);
    sails.honeypot.checkRequest = function requestIsSpan(req, cb) {
       // skip spam test for test env
      if(sails.config.environment === 'test' &&
        !sails.config.auth.honeypot.checkInTests )
        return cb();
      // then do the ip check
      sails.honeypot.query(req.ip, function(err, resp) {
        if (err) return cb(err);
        // dont are in honeypot then dont are a spam
        if (!resp.found) return cb(null, false);

        var maxThreatScore = sails.config.auth.honeypot.maxThreatScore;
        if (maxThreatScore) {
          if (resp.threatScore > maxThreatScore) {
            //are spam
            return cb(null, true);
          }
        }

        if (resp.type.spammer) {
          // are flagged as spammer
          return cb(null, true);
        }

        // not is spam
        return cb();
      });
    }
  }

  cb();
};
