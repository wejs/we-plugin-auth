/**
 * We.js auth module
 *
 * @author Alberto Souza <contato@albertosouza.net>
 * @license MIT
 */
const auth = {
  util: require('./util.js'),
  logIn: require('./logIn.js'),
  logOut: require('./logOut.js')
};

//exports it!
module.exports = auth;