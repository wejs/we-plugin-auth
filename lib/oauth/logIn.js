/**
 * Login one user and set its access token
 *
 * @param  {object}   request
 * @param  {object}   response
 * @param  {object}   newUser
 * @param  {Function} cb
 */
module.exports = function logIn(req, res, newUser, cb) {
  var sails = req._sails;
  var domain = sails.config.auth.cookieDomain;
  var name = sails.config.auth.cookieName;
  var cookieSecure = sails.config.auth.cookieSecure;

  sails.models.accesstoken.create({
    userId: newUser.id
  })
  .exec(function(err, tokenObj) {
    if(err) {
      sails.log.error('Error on generate token for user', err);
      return cb(err);
    }

    var options = {};
    if(domain) options.domain = domain;
    if(cookieSecure) options.secure = cookieSecure;

    res.cookie(name, tokenObj.token, options);

    cb(null, tokenObj);
  });
}
