/**
 * We.js oauth2 util functions and helpers
 * @author Alberto Souza <contato@albertosouza.net>
 * @license [url] MIT
 */
const util = {
  /**
   * Get access token from requst param
   *
   * Getter order :
   *   Header Authorization
   *   req.cookie
   *   req.param
   *   req.session
   *
   * @param  {object} req express request param
   * @return {string}     return the token string or null
   */
  parseToken(req) {
    const we = req.we;
    let accessToken;

    if (req.header) {
      // get from bearer header Authorization
      accessToken = req.header('Authorization');
      if (accessToken) {
        let token = accessToken.split(' ');
        if (token && token[0] === 'Bearer') {
          return token[1];
        }
      }
    }

    if (req.cookies) {
      // get from cookie
      if (req.cookies && req.cookies[we.config.passport.cookieName]) {
        return req.cookies[we.config.passport.cookieName];
      }
    }

    // get from query string or body param
    if (req.query && req.query.access_token) {
      return req.query.access_token;
    }
    // get from session
    if (req.session && req.session.authToken) {
      return req.session.authToken;
    }

    return null;
  },

  /**
   * Check if one token is expired
   *
   * @param  {object} token           AccessToken record
   * @param  {int} accessTokenTime    valid token max time
   * @return {boolean}
   */
  checkIfTokenIsExpired(token, accessTokenTime) {
    // skip if dont set accessToken time
    if(!accessTokenTime) return true;
    // check if cache is valid
    const dateNow =  new Date().getTime(),
      timeDiference = dateNow - token.createdAt;
    // if cache is valid return cached page data
    if (timeDiference <= accessTokenTime) {
      // is valid
      return true;
    } else {
      // is expired
      return false;
    }
  },

  /**
   * Expire one user token
   *
   * @param  {string} token     AccessToken string
   * @param  {string} userId    valid token max time
   * @param  {function} cb      callback(err,results);
   */
  expireToken(token, app, cb) {
    return app.db.models.accesstoken
    .update({
      isValid: false
    },{
      where: { token: token },
    })
    .nodeify(cb)
  },
  /**
   * Check is user is authenticated
   * based on passport npm package
   *
   * @param  {object}  req express.js request object
   * @return {Boolean}
   */
  setIsAuthenticated(req) {
    // add one isAuthenticated function on every req object
    req.isAuthenticated = function checkIfIsAuthenticated() {
      if (req.user && req.user.id) {
        return true;
      }
      return false;
    }
  }
};

module.exports = util;