/**
 * We.js oauth2 provider logic
 *
 * @author Alberto Souza <contato@albertosouza.net>
 * @license [url] MIT
 */

var provider = {}
  , util = require('./util.js')
  , logIn = require('./logIn.js');

/**
 * Provider Sails.js hook
 */
provider.sailsHook = function () {
  return {
   // Implicit default configuration
    // (mixed in to `sails.config`)
    defaults: {
      maxAge: 36000000
    },

    /**
     * initialize hook
     *
     * @param  {Function} cb  callback
     */
    initialize: function (cb) {
      cb();
    },

    routes: {
      before: {
        '/*': provider.init()
      }
    }
  }
}


/**
 * Init configure and return oauth2 provider middleware
 *
 * @return {function} configured express midleware
 */
provider.init = function() {
  // pre configure things for all requests here
  return provider.middleware;
}

provider.middleware = function (req, res, next) {
  provider.validAndLoadAccessTokenMW(req, res,function() {
    // set req.isAuthenticated function
    // how mimics same funcion from passport
    util.setIsAuthenticated(req);
    // after load current user delete access token from query params
    // this interferes in some old versions ( - 0.10.2 ) of sails.js blueprint
    if (req.query.access_token)
      delete req.query.access_token;
    next();
  });
}

/**
 * Valid and load Acces token in provider server
 *
 * @param  {object}   req  express request
 * @param  {object}   res  express response
 * @param  {Function} next
 */
provider.validAndLoadAccessTokenMW = function (req, res, next) {
  // TODO move to oauth2 configuration
  var accessTokenTime = req._sails.getConfig('wejs.accessTokenTime');

  provider.validConsumerAcessToken(req, accessTokenTime,
  function(err, validResponse) {
    if (err) {
      req._sails.log.error('Error on valid access token', err);
      return res.serverError({
        error: 'Error on validate access token'
      });
    }

    // invalid token
    if (!validResponse.isValid) {
      res.accessTokenError = validResponse;
      // no auth token, user dont are authenticated
      return next();
    }

    req.user = validResponse.user;
    // set accessToken on req for use in others middlewares
    req.accessToken = validResponse.token;
    return next();
  });
}

provider.validConsumerAcessToken = function (req, accessTokenTime, callback) {
  var token = util.parseToken(req);

  // auth token not found
  if (!token) return callback(null, {
    isValid: false,
    errorCode: 'notFound',
    error: 'access token not found'
  });

  AccessToken.findOne({
    token: token,
    isValid: true
  })
  .exec(function (err, tokenObj) {
    if (err) return callback(err, null);

    // not found in provider database
    if (!tokenObj) return callback(null, {
      isValid: false,
      errorCode: 'notFound',
      error: 'access token not found'
    });

    var notIsExpired = util.checkIfTokenIsExpired(tokenObj, accessTokenTime);

    if (!notIsExpired) {
    // expired
      return callback(null, {
        isValid: false,
        errorCode: 'expired',
        error: 'Auth token exprired'
      });
    }

    // TODO add suport to oauth scopes
    User.findOneById(tokenObj.userId)
    .exec(function (err, user) {
      if (err) return callback(err, null);

      if (!user) {
        // user not found ... .
        // a token without user dont are valid ...
        return callback(null, {
          isValid: false,
          errorCode: 'notFound',
          error: 'Auth token not found'
        });
      }

      // token is valid!
      var email = user.email;
      // set and delete some default vars
      user = user.toJSON();
      // clone it to dont run toJSON again
      user = _.clone(user);
      // re-set email ... it are deleted in toJSON
      user.email = email;

      return callback(null, {
        isValid: true,
        token: token,
        user: user
      });
    });

  });
}

/**
 * Respond to consumer or redirect to home page
 *
 * @param  {object} req   express request
 * @param  {object} res   express response
 */
provider.respondToConsumer = function resConsumerOk(req, res) {
  var service = sails.config.oauth.services[res.locals.service];

  if (!service) {
    sails.log.warn('Invalid service', res.locals.service);
    return res.badRequest();
  }

  provider.generateAccessToken(req.user, req, res, function (err, accessToken) {
    req.accessToken = accessToken;

    if (res.locals.service && service) {
      var callbackUrl = service.callbackUrl + '/' + req.accessToken.token;
      if ( res.locals.returnUrl ) callbackUrl += '?redirectTo=' + res.locals.returnUrl;
      return res.redirect(callbackUrl);
    }

    if (res.locals.consumerId) {
      sails.log.warn('TODO suport to consumers');
    }

    // if dont have consumer or service redirect to accounts home
    return res.redirect('/');
  });

}

/**
 * Generate one access token for user
 *
 * @param  {object}   user     user how are the token owner
 * @param  {object}   req      express.js request
 * @param  {object}   res      express.js response
 * @param  {Function} callback   after end run callback(err, accessToken);
 */
provider.generateAccessToken = function generateAccessToken(user, req, res, callback) {
  RefreshToken.create({
    'userId': user.id
  })
  .exec(function(error, refreshToken) {
    if (error) {
      sails.log.error('Error on create Refresh token:',error);
      return res.serverError(error);
    }

    AccessToken.create({
      'userId': user.id,
      'refreshToken': refreshToken.token
    })
    .exec(function(error, accessToken) {
      if (error) {
        sails.log.error('Error on create accessToken:',error);
        return res.serverError(error);
      }
      callback(null, accessToken);
    });
  });
}

module.exports = provider;
