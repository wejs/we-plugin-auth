
var WA = function(sails) {
  // sails hook for sails => 0.11.x
  return {
    /**
     * Default configuration
     *
     * We do this in a function since the configuration key for
     * the hook is itself configurable, so we can't just return
     * an object.
     */
    defaults: {
      auth: {
        // in current we.js version OR is provider OR consumer
        isProvider: false,
        isConsumer: true,
        enableLogin: true,

        providerDomain: true,

        cookieDomain: '.cdp.dev',
        cookieName: 'wetoken',
        cookieMaxAge: 900000,
        cookieSecure: false,

        honeypot: {
          // add a honeypot key to enable this feature
          key: null,
          maxThreatScore: 80,
          // enable honeypot check in tests?
          checkInTests: false
        }
      },
      oauth: {
        services: {}
      }
    },

   /**
     * Initialize the hook
     * @param  {Function} cb Callback for when we're done initializing
     */
    initialize: function(cb) {
      cb();
    }
  }
};

// plugin init function
WA.init = require('./init.js');

module.exports = WA;
