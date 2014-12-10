module.exports = function initPlugin(sails, cb) {
  var weOauth2 = require('we-oauth2');
  var weOauth2Middleware;

  // bind passport hook
  // TODO remove passport dependency
  var wePassport = require('we-passport');
  // TODO remove passport dependency
  var passportMiddleware =  wePassport.init(sails);

  // login / logout middleware
  if(sails.config.auth.isProvider) {
    weOauth2Middleware = weOauth2.provider.init();
  } else {
    weOauth2Middleware = weOauth2.consumer.init();
  }

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

  // - OAUTH code
  // on sails.js router:before event ...
  sails.on('router:before',function onOauthPluginRouterBefore() {
    sails.router.bind('/*', function (req, res, next) {
      passportMiddleware(req, res, next);
    });

    // run weOauth2Middleware arter passport middleware
    // this middleware sets the req.user param
    sails.router.bind('/*', weOauth2Middleware);

    // set default locals vars for dont show undefined errors on template rendering
    sails.router.bind('/*', function setDefaultLocalsVars(req, res, next) {
      res.locals.errors = [];
      res.locals.providers = null;
      res.locals.service = req.param('service');
      res.locals.consumerId = req.param('consumerId');

      return next();
    });

    sails.emit('we:passport:bind:after', sails);
  });

  // on we.js we:passport:bind:after ...
  sails.on('we:passport:bind:after',function afterBindPassport() {
    if(!sails.config.auth.isProvider) return;

    return sails.router.bind('/*', function checkIfNeedToRedirect(req, res, next) {
      var serviceName = req.param('service');
      var sessionService = req.session.serviceName;
      var service = sails.config.oauth.services[serviceName];

      if(service) res.locals.service = serviceName;

      if (req.session.resetPassword) return next();

      if (req.isAuthenticated()) {
        if (sessionService) {
          res.locals.service = sessionService;
          delete req.session.serviceName;
          return weOauth2.provider.respondToConsumer(req, res);
        } else {
          if(service) {
            return weOauth2.provider.respondToConsumer(req, res);
          }
        }
      } else if(serviceName && !sessionService) {
        if ( service ) {
          req.session.serviceName = serviceName;
        } else {
          sails.log.warn('Invalid service', serviceName);
        }
      }
      return next();
    });
  });


  cb();
};
