var wePassport = require('we-passport');

module.exports = function initPlugin(sails, cb) {
  // initialize passport configs
  var passportMiddleware =  wePassport.init(sails);

  // on router:before event ...
  sails.on('router:before',function () {
    // bind passport hook
    sails.router.bind('/*', function (req, res, next) {
      passportMiddleware(req, res, next);
    });

    sails.emit('we:passport:bind:after', sails);
  });

  cb();
};
