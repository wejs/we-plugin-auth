/**
 * AuthToken
 *
 * @module      :: Model
 * @description :: Auth Token model for create login, password and activate account tokens
 *
 */
var crypto = require('crypto');

module.exports = {
  schema: true,
  attributes: {

    userId: {
      type: 'string',
      required: true
    },

    providerUserId: {
      type: 'string'
    },

    tokenProviderId: {
      type: 'string'
    },

    tokenType: {
      type: 'string'
    },

    token: {
      type: 'string',
      defaultsTo: true
    },

    isValid: {
      type: 'boolean',
      defaultsTo: true
    },

    getResetUrl: function() {
      return sails.config.hostname + '/auth/'+ this.userId +'/reset-password/' + this.token
    }
  },

  beforeCreate: function(token, next) {
    if (token.userId) {
      // before invalid all user old tokens
      AuthToken.invalidOldUserTokens(token.userId, function(err, result){
        // generete new token
        token.token = crypto.randomBytes(25).toString('hex');
        next();
      });
    }else{
      next();
    }
  },

  /**
   * Invalid old user tokens
   * @param  {string}   uid  user id to invalid all tokens
   * @param  {Function} next callback
   */
  invalidOldUserTokens: function(uid, next) {
    AuthToken.update({ userId: uid }, { isValid : false })
    .exec(function(err,results){
      if(err){
        sails.log.error(err);
        return next(err);
      }
      next(null, results);
    });
  },


  /**
  * Check if a auth token is valid
  */
  validAuthToken: function (userId, token, cb) {

    // then get user token form db
    AuthToken.findOneByToken(token).exec(function(err, authToken) {
      if (err) {
        return cb('Error on get token', null);
      }

      // auth token found then check if is valid
      if(authToken){

        // user id how wons the auth token is invalid then return false
        if(authToken.userId !== userId || !authToken.isValid){
          return cb(null, false,{
            result: 'invalid',
            message: 'Invalid token'
          });
        }

        // TODO implement expiration time


        // set this auth token as used
        authToken.isValid = false;
        authToken.save(function(err){
          if (err) {
            return cb(res.i18n("DB Error"), false);
          }
          // authToken is valid
          return cb(null, true, authToken);
        });

      } else {
        // auth token not fount
        return cb('Auth token not found', false, null);
      }

    });
  }

};
