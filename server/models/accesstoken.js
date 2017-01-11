/**
 * accessToken
 *
 * @module      :: Model
 * @description :: Token model for bearer token access
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

      providerUserId: {
        type: we.db.Sequelize.STRING
      },

      tokenProviderId: {
        type: we.db.Sequelize.STRING
      },

      tokenType: {
        type: we.db.Sequelize.STRING
      },

      token: {
        type: we.db.Sequelize.STRING,
        allowNull: false
      },

      isValid: {
        type: we.db.Sequelize.BOOLEAN,
        defaultValue: true
      }
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
        * Check if a access token is valid
        */
        validAccessToken(userId, token, cb) {
          // then get user token form db
          we.db.models.accesstoken.find({ where: {
            token: token
          }})
          .nodeify(function (err, accessToken) {
            if (err) return cb(err)
            // access token found then check if is valid
            if (accessToken) {
              // user id how wons the access token is invalid then return false
              if(accessToken.userId !== userId || !accessToken.isValid){
                return cb(null, false,{
                  result: 'invalid',
                  message: 'Invalid token'
                });
              }
              // set this access token as used
              accessToken.isValid = false;
              accessToken
              .save()
              .then( ()=> {
                // accessToken is valid
                cb(null, true, accessToken);
                return null;
              })
              .catch(cb);
            } else {
              // Access token not found
              return cb('Access token not found', false, null);
            }
          })
        }
      },

      instanceMethods: {
        toJSON() {
          if (!this.get) {
            console.trace();
          }

          const obj = this.get();
          delete obj.updatedAt;
          return obj;
        }
      },
      hooks: {
        beforeValidate(token, options, next) {
          if (!token.token) {
            // generate the token string
            token.token = crypto.randomBytes(25).toString('hex');
          }

          next(null, token);
        }
      }
    }
  }

  return model;
}
