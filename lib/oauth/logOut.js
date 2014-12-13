/**
 * Log out current user
 *
 * @param  {object}   request
 * @param  {object}   response
 * @param  {Function} cb
 */
module.exports = function logOut(req, res, cb) {
  var sails = req._sails;
  var domain = sails.config.auth.cookieDomain;
  var name = sails.config.auth.cookieName;
  var cookieSecure = sails.config.auth.cookieSecure;

  var options = {};
  if(domain) options.domain = domain;
  if(cookieSecure) options.secure = cookieSecure;
  res.clearCookie(name, options);
  cb();
}
