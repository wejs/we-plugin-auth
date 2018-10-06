/**
 * Main we-plugin-auth file
 *
 * see http://wejs.org/docs/we/plugin
 */
const wePassport = require('./lib/passport');

module.exports = function loadPlugin(projectPath, Plugin) {
  const plugin = new Plugin(__dirname);

  /**
   * We.js fast loader function
   * Disables auto load for this plugin
   *
   * @param  {Object}   we   We.js app
   * @param  {Function} done callback
   */
  plugin.fastLoader = function fastLoader(we, done) {
    // controllers:
    we.controllers.auth = new we.class.Controller(
      require('./server/controllers/auth.js')
    );

    // - Models

    we.db.modelsConfigs.accesstoken = require('./server/models/accesstoken.js')(we);
    we.db.modelsConfigs.authtoken = require('./server/models/authtoken.js')(we);
    we.db.modelsConfigs.passport = require('./server/models/passport.js')(we);
    we.db.modelsConfigs.password = require('./server/models/password.js')(we);

    done();
  };

  plugin.setConfigs({
    passport: {
      // session is required for local strategy
      enableSession: true,

      accessTokenTime: 300000000,
      cookieDomain: 'localhost:' + ( process.env.PORT || '3000' ),
      cookieName: 'weoauth',
      cookieSecure: false,
      expiresTime: 31536000000, // time to expires token and session

      strategies: {
        // session
        local: {
          Strategy: require('passport-local').Strategy,
          // url to image icon
          icon: '/public/plugin/we-core/files/images/login.png',
          authUrl: '/login',

          usernameField: 'email',
          passwordField: 'password',
          session: true,
          findUser(email, password, done) {
            const we = this.we;
            // build the find user query
            let query = { where: {} };
            query.where[we.config.passport.strategies.local.usernameField] = email;
            // find user in DB
            we.db.models.user
            .find(query)
            .then ( (user)=> {
              if (!user) {
                done(null, false, { message: 'auth.login.wrong.email.or.password' });
                return null;
              } else if (user.blocked) {
                done(null, false, { message: 'auth.login.user.blocked' });
                return null;
              }
              // get the user password
              return user.getPassword()
              .then( (passwordObj)=> {
                if (!passwordObj) {
                  done(null, false, { message: 'auth.login.user.dont.have.password' });
                  return null;
                }

                passwordObj.validatePassword(password, (err, isValid)=> {
                  if (err) return done(err);
                  if (!isValid) {
                    return done(null, false, { message: 'auth.login.user.incorrect.password.or.email' });
                  } else {
                    return done(null, user);
                  }
                })

                return null;
              })
            })
            .catch(done);
          }
        }
      }
    },
    auth : {
      // flags to enable or disable the login and register
      allowLogin: true,
      allowRegister: true,
      requireAccountActivation: true
    },
    // overridable by systemSettings {recaptchaKey, recaptchaSecret}
    apiKeys: {
      // add google recaptcha key and secret in project config/local.js file for enable this feature
      // Requires cliend side recaptcha implementation in registration form how is avaible in we-plugin-form
      recaptcha: {
        key: null,
        secret: null
      }
    },

    publicSystemSettings: {
      recaptchaKey: true
    },

    emailTypes: {
      AccontActivationEmail: {
        label: 'Email de ativação após cadastro de conta de usuário',
        templateVariables: {
          confirmUrl: {
            example: '/#example',
            description: 'URL de confirmação de conta de usuário'
          },
          username: {
            example: 'albertosouza',
            description: 'Nome único do novo usuário'
          },
          displayName: {
            example: 'Alberto',
            description: 'Nome de exibição do novo usuário'
          },
          fullName: {
            example: 'Alberto Souza',
            description: 'Nome completo do novo usuário'
          },
          email: {
            example: 'alberto@linkysystems.com',
            description: 'Email do novo usuário'
          },
          siteName: {
            example: 'Site Name',
            description: 'Nome desse site'
          },
          siteUrl: {
            example: '/#example',
            description: 'URL desse site'
          }
        }

      },
      AuthResetPasswordEmail: {
        label: 'Email de troca de senha',
        templateVariables: {
          username: {
            example: 'alberto',
            description: 'Nome único do usuário'
          },
          displayName: {
            example: 'Alberto',
            description: 'Nome de exibição do usuário'
          },
          siteName: {
            example: 'Site Name',
            description: 'Nome desse site'
          },
          siteUrl: {
            example: '/#example',
            description: 'URL desse site'
          },
          resetPasswordUrl: {
            example: 'http://linkysystems.com/example',
            description: 'URL de resetar a senha do usuário'
          }
        }
      },
      AuthChangePasswordEmail: {
        label: 'Email de aviso de troca de senha',
        templateVariables: {
          username: {
            example: 'alberto',
            description: 'Nome único do usuário'
          },
          displayName: {
            example: 'Alberto',
            description: 'Nome de exibição do usuário'
          },
          siteName: {
            example: 'Site Name',
            description: 'Nome desse site'
          },
          siteUrl: {
            example: '/#example',
            description: 'URL desse site'
          }
        }
      }
    }
  });

  plugin.setRoutes({
    'get /account': {
      'controller': 'auth',
      'action': 'current',
      'model': 'user'
    },
    'get /signup': {
      'controller': 'auth',
      'action': 'signup',
      'template': 'auth/register',
      'titleHandler'  : 'i18n',
      'titleI18n': 'Register',
      'breadcrumbHandler': 'auth'
    },
    'post /signup': {
      'controller': 'auth',
      'action': 'signup',
      'template': 'auth/register',
      'titleHandler'  : 'i18n',
      'titleI18n': 'Register',
      'breadcrumbHandler': 'auth'
    },
    'get /login': {
      'controller': 'auth',
      'action': 'login',
      'titleHandler'  : 'i18n',
      'titleI18n': 'Login',
      'template': 'auth/login',
      'breadcrumbHandler': 'auth'
    },
    'post /login': {
      'controller': 'auth',
      'action': 'login',
      'titleHandler'  : 'i18n',
      'titleI18n': 'Login',
      'template': 'auth/login',
      'breadcrumbHandler': 'auth'
    },
    'post /auth/login': {
      'controller'    : 'auth',
      'action'        : 'login',
      'breadcrumbHandler': 'auth'
    },
    '/auth/logout': {
      'controller'    : 'auth',
      'action'        : 'logout',
      'breadcrumbHandler': 'auth'
    },
    'get /auth/forgot-password': {
      'titleHandler'  : 'i18n',
      'titleI18n'     : 'auth.forgot-password',
      'controller'    : 'auth',
      'action'        : 'forgotPassword',
      'template'      : 'auth/forgot-password',
      'breadcrumbHandler': 'auth'
    },
    'post /auth/forgot-password': {
      'titleHandler'  : 'i18n',
      'titleI18n'     : 'auth.forgot-password',
      'controller'    : 'auth',
      'action'        : 'forgotPassword',
      'template'      : 'auth/forgot-password',
      'breadcrumbHandler': 'auth'
    },
    'get /auth/:id([0-9]+)/reset-password/:token': {
      'controller': 'auth',
      'action': 'consumeForgotPasswordToken',
      'breadcrumbHandler': 'auth'
    },
    'get /api/v1/auth/check-if-can-reset-password': {
      'controller': 'auth',
      'action': 'checkIfCanResetPassword',
      'responseType'  : 'json'
    },
    'post /auth/change-password': {
      'titleHandler'  : 'i18n',
      'titleI18n'     : 'auth.change-password',
      'controller'    : 'auth',
      'action'        : 'changePassword',
      'template'      : 'auth/change-password',
      'breadcrumbHandler': 'auth'
    },
    'get /auth/change-password': {
      'titleHandler'  : 'i18n',
      'titleI18n'     : 'auth.change-password',
      'controller'    : 'auth',
      'action'        : 'changePassword',
      'template'      : 'auth/change-password',
      'breadcrumbHandler': 'auth'
    },
    'get /user/:id([0-9]+)/activate/:token':{
      'controller'    : 'auth',
      'action'        : 'activate',
      'breadcrumbHandler': 'auth'
    },
    'post /auth/auth-token':{
      'controller'    : 'auth',
      'action'        : 'authToken',
      'breadcrumbHandler': 'auth'
    },
    'get /auth/:id([0-9]+)/new-password': {
      'titleHandler'  : 'i18n',
      'titleI18n'     : 'auth.new-password',
      'controller'    : 'auth',
      'action'        : 'newPassword',
      'template'      : 'auth/new-password',
      'breadcrumbHandler': 'auth'
    },
    'post /auth/:id([0-9]+)/new-password': {
      'titleHandler'  : 'i18n',
      'titleI18n'     : 'auth.new-password',
      'controller'    : 'auth',
      'action'        : 'newPassword',
      'template'      : 'auth/new-password',
      'breadcrumbHandler': 'auth'
    }
  });

  plugin.onSetPassport = function onSetPassport(we, done) {
    we.log.verbose('initPassport step');
    // - Passports configs
    wePassport.configureAndSetStrategies(we);

    we.express.use(function setRequestLocaleIfIsAuthenticated(req, res, next) {
      if (
        req.user &&
        req.user.language &&
        we.config.i18n.locales.indexOf(req.user.language) > -1
      ) {
        // user locale
        req.setLocale(req.user.language);
        // update locale for views
        res.locals.locale = req.getLocale();
      }

      next();
    });

    we.events.emit('we:after:load:passport', we);
    // admin env middleware
    we.express.get('/admin*', function adminPage(req ,res, next) {
      res.locals.isAdmin = true;
      return next();
    });

    done();
  }

  plugin.setUserModelMethods = function setUserModelMethods(we, done) {

    we.db.modelsConfigs.user.options.instanceMethods.getPassword = function getPassword (){
      return we.db.models.password.findOne({
        where: { userId: this.id }
      });
    };
    we.db.modelsConfigs.user.options.instanceMethods.verifyPassword = function verifyPassword (password, cb){
      return this.getPassword()
      .nodeify( function(err, passwordObj) {
        if (err) return cb(err)

        if (!passwordObj) return cb(null, false)
        passwordObj.validatePassword(password, cb)
      })
    };
    we.db.modelsConfigs.user.options.instanceMethods.updatePassword = function updatePassword (newPassword, cb){
      var user = this;
      return this.getPassword()
      .nodeify( function (err, password) {
        if (err) return cb(err);

        if (!password) {
          // create one password if this user dont have one
          we.db.models.password
          .create({
            userId: user.id,
            password: newPassword
          })
          .then( (password)=> {
            cb(null, password);
            return null;
          })
        } else {
          // update
          password.password = newPassword;
          password.save()
          .then( (r)=> {
            cb(null, r);
            return null;
          });
        }

        return null;
      })
    }

    done();
  }

  plugin.hooks.on('we:before:load:plugin:features', (we, done)=> {
    we.antiSpam = require('./lib/antiSpam');
    // load we.js auth logic
    we.auth = require('./lib');

    done();
  });

  // hooks and events
  plugin.hooks.on('we-core:on:set:passport', plugin.onSetPassport);
  plugin.hooks.on('we:models:before:instance', plugin.setUserModelMethods);

  return plugin;
};