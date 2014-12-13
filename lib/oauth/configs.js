/**
 * We.js oauth2 configuration logic
 *
 * @todo! configuration dont are implemented
 *
 * @author Alberto Souza <contato@albertosouza.net>
 * @license [url] MIT
 */

// -- default configs --
var configs = {};

/**
 * Get configs from sails.js
 * @TODO Add suport to configs
 */
configs.get = function() {
  if (typeof sails === 'undefined') {
    console.error('Sails.js not found! but is required for we-passport!');
    return null;
  }
};

module.exports = {};
