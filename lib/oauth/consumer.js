/**
 * We.js oauth2 consumer logic
 * @author Alberto Souza <contato@albertosouza.net>
 * @license [url] MIT
 */

var consumer = {}
  , util = require('./util.js')
  , logOut = require('./logOut.js')
  , request = require('request');

/**
 * Consumer Sails.js hook
 */
consumer.sailsHook = function () {
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
        '/*': consumer.init()
      }
    }
  }
}

/**
 * Init configure and return oauth2 consumer middleware
 *
 * @return {function} configured express midleware
 */
consumer.init = function() {
  // pre configure things for all requests here

  // then return the middleware
  return consumer.middleware;
}

consumer.middleware = function (req, res, next) {
  consumer.validAndLoadAccessTokenMW(req, res,function() {
    consumer.loadUserAfterTokenMW(req, res, function() {
      // set req.isAuthenticated function
      util.setIsAuthenticated(req);

      // after load current user delete access token from query and body params
      // TODO find a form to change req.options.critera.blacklist with access_token in all requests
      if (req.query.access_token){
        delete req.query.access_token;
      }
      if (req.body && req.body.access_token){
        delete req.body.access_token;
      }

      next();
    });
  });
}

consumer.receiveToken = function(req, res, next) {
  consumer.validAndLoadAccessTokenMW(req, res,function() {
    consumer.loadUserAfterTokenMW(req, res, function() {
      next();
    });
  });
}

consumer.validAndLoadAccessTokenMW = function (req, res, next) {
  var accessToken = util.parseToken(req),
    sails = req._sails;

  // auth token not found
  if (!accessToken) return next();

  consumer.getAccessTokenFromDB(accessToken,function(err, token) {
    if (err) {
      console.error('Error on get token from db', err);
    }

    if (token) {
      // invalid token
      if ( !token.isValid ) {
        // if token dont are valid log out user to delete its token
        return logOut(req, res, next);
      }
      // set accessToken on req for use in others middlewares
      req.accessToken = token;
      return next();
    } else {
      // skip valid and load token from provider in socket.io requests
      if (req.isSocket) return next();

      var validationUrl = sails.config.wejs.providers.accounts + '/api/v1/oauth2/validate-token';
      consumer.validTokenOnProviderServer(accessToken, validationUrl , function(err, tokenResp) {
        if (err) {
          console.error('Error on get token from provider server', err);
        }

        // if not is valid
        if (!tokenResp || !tokenResp.isValid) {
          req.accessTokenError = tokenResp;
          return logOut(req, res, next);
        }

        var tokenUser = tokenResp.user;
        delete tokenResp.user;

        var tokenStrig;
        if(tokenResp.token.token) {
          tokenStrig = tokenResp.token.token;
        } else {
          tokenStrig = tokenResp.token;
        }

        getOrCreateUser(tokenUser, function(err, user) {
          if (err) {
            console.error('Error find od create user', err);
            return next(err);
          }

          // save id in provider
          if (!user.idInProvider) {
            user.idInProvider = tokenUser.id;
            user.save();
          }

          // set logged in user
          req.user = user;
          var newToken = {
            userId: user.id,
            tokenType: 'access',
            token: tokenStrig
          };

          // cache token on consumer DB
          AccessToken.create(newToken)
          .exec(function (err, salvedToken) {
            if (err) {
              sails.log.error('Error on save validated token', err, tokenResp);
            }
            // set accessToken on req for use in others middlewares
            req.accessToken = salvedToken;
            return next();
          })
        })
      });
    }
  });
}

function getOrCreateUser (tokenUser, callback) {
  User.findOne({ idInProvider: tokenUser.id })
  .exec(function (err, user) {
    if (err) {
      console.error('Error find user by id in provider', err);
      return callback(err);
    }

    if(user) return callback(null, user);

    User.findOne({
      email: tokenUser.email
    }).exec(function (err, user) {
      if (err) {
        console.error('Error find user by email', err);
        return callback(err);
      }

      if(user) return callback(null, user);

      sails.log.info('New user from oauth will be created:', tokenUser);

      // TODO check cpf
      // user not found then create it
      User.create({
        username: tokenUser.username,
        biography: tokenUser.biography,
        displayName: tokenUser.displayName,
        language: tokenUser.language,
        idInProvider: tokenUser.id,
        email: tokenUser.email,
        active: true
      }).exec(callback);
    });
  });
}

consumer.getAccessTokenFromDB = function (token, callback) {
  // check if access token are on DB
  AccessToken.findOne({
    token: token
  })
  .exec(function (err, token) {
    callback(err, token);
  });
};

consumer.validTokenOnProviderServer = function (token, validationUrl, callback) {
  request.post({
    url: validationUrl,
    json: true,
    form: { access_token: token },
    timeout: 5000
  }, function (err, r, data) {
    callback(err, data);
  });
}

consumer.parseReceivedToken = function () {

}

/**
 * Load user after get token
 * use only on provider server
 *
 * @param  {object}   req  express request
 * @param  {object}   res  express response
 * @param  {Function} next
 */
consumer.loadUserAfterTokenMW = function loadUserAfterTokenMW(req, res, next) {

  if (!req.accessToken || !req.accessToken.userId) {
    return next();
  }

  User.findOneById(req.accessToken.userId)
  .exec(function (err, user) {
    if (err) {
      sails.log.error('loadUserAfterToken:Error on get user with auth token',err,req.accessToken);
      return next();
    }

    req.user = user;
    next();
  })
}

module.exports = consumer;
