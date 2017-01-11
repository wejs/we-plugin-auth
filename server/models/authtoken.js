/**
 * AuthToken
 *
 * @module      :: Model
 * @description :: Auth Token model for create login, password and activate account tokens
 *
 */
const crypto = require('crypto');

module.exports = function Model(we) {
  // set sequelize model define and options
  const model = {
    definition: {

      userId: {
        type: we.db.Sequelize.BIGINT,
        allowNull: false
      },

      providerUserId: { type: we.db.Sequelize.BIGINT },
      tokenProviderId: { type: we.db.Sequelize.STRING },
      tokenType: { type: we.db.Sequelize.STRING },

      token: {
        type: we.db.Sequelize.STRING,
        defaultValue: true
      },

      isValid: {
        type: we.db.Sequelize.BOOLEAN,
        defaultValue: true
      },

      redirectUrl: { type: we.db.Sequelize.STRING }
    },

    options: {

      enableAlias: false,
      classMethods: {
        /**
         * Invalid old user tokens
         * @param  {string}   uid  user id to invalid all tokens
         * @param  {Function} next callback
         */
        invalidOldUserTokens(uid, next) {
          we.db.models.authtoken
          .update(
            { isValid : false },
            { where: {
              userId: uid
            }}
          )
          .nodeify(next)
        },

        /**
        * Check if a auth token is valid
        */
        validAuthToken(userId, token, cb) {
          // then get user token form db
          we.db.models.authtoken
          .findOne({ where: {
            token: token,
            userId: userId
          }})
          .then(function (authToken) {
            // auth token found then check if is valid
            if (!authToken) {
              // auth token not fount
              return cb (null, false, null)
            } else if(authToken.userId != userId || !authToken.isValid) {
            // user id how wons the auth token is invalid then return false
              cb(null, false,{
                result: 'invalid',
                message: 'Invalid token'
              });
            } else  {
              return authToken
              .destroy()
              .then(function () {
                // authToken is valid
                cb(null, true, authToken);

                return null;
              })
            }

            return null;
          })
          .catch(cb)
        }

      },

      instanceMethods: {
        getResetUrl() {
          return we.config.hostname + '/auth/'+ this.userId +'/reset-password/' + this.token;
        },
        toJSON() {
          const obj = this.get();
          return obj;
        }
      },
      hooks: {
        beforeCreate(token, options, next) {
          if (token.userId) {
            // before invalid all user old tokens
            we.db.models.authtoken.invalidOldUserTokens(token.userId, function() {
              // generete new token
              token.token = crypto.randomBytes(25).toString('hex');
              next(null, token);
            });
          } else {
            next(null, token);
          }
        }

      }
    }
  }

  return model;
}