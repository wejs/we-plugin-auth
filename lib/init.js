var wePassport = require('we-passport');
// initialize passport configs
var passportMiddleware =  wePassport.init();

module.exports = function initPlugin(sails, cb) {
  // on router:before event ...
  sails.on('router:before',function () {
    // bind passport hook
    return sails.router.bind('/*', function (req, res, next) {

      passportMiddleware(req, res, next);
      // // Initialize Passport
      // passport.initialize()(req, res, function () {
      //   // Use the built-in sessions
      //   passport.session()(req, res, function () {
      //     // Make the user available throughout the frontend
      //     res.locals.user = req.user;

      //     next();
      //   });
      // });
    });
  });

  // on ready load passport strategies
  // sails.on('ready',function () {
  //   return sails.services.passport.loadStrategies();
  // });

  cb();
};
