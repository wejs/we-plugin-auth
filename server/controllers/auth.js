/**
 * Authentication controller
 */

const lt = require('../../lib/loginThrottle.js');

module.exports = {
  _config: { acl: false },
  /**
   * Getter for current logged in user
   */
  current(req, res) {
    if (!req.isAuthenticated() ) return res.send({});

    if (req.user.blocked) {
      req.we.log.warn('auth.user.blocked.on.current', req.user.id);
      return res.badRequest('auth.user.blocked');
    }

    return res.ok(req.user);
  },
  /**
   * Signup action for POST and GET methods
   */
  signup(req, res) {
    const we = req.we;
    // check allowRegister flag how block signup
    if (!we.config.auth.allowRegister) return res.forbidden();
    // anti spam honeypot field
    if (req.body.mel) {
      we.log.info('Bot get mel:', req.ip, req.body.email);
      return res.forbidden();
    }

    if (req.method !== 'POST' || req.isAuthenticated()) {
      return res.ok();
    }

    let newUser, requireAccountActivation;
    // --  set req.body for handle db errors
    res.locals.data = req.body;

    we.utils.async.series([
      function checkIfIsSpam(cb) {
        we.antiSpam.recaptcha.verify(req, res, (err, isSpam)=> {
          if (err) return cb(err);
          if (isSpam) {
            we.log.warn('auth.signup: spambot found in recaptcha verify: ', req.ip, req.body.email);

            res.addMessage('warning', {
              text: 'auth.register.spam',
              vars: { email: req.body.email }
            });

            return res.queryError();
          }

          requireAccountActivation = we.config.auth.requireAccountActivation;
          // if dont need a account activation email then create a active user
          if (!requireAccountActivation) req.body.active = true;

          cb();
        });
      },
      function checkUSerAcceptTermsField(cb) {
        if (!req.body.acceptTerms || req.body.acceptTerms == 'false') {
          cb('auth.register.acceptTerms.required');
        } else {
          cb();
        }
      },
      // save the user and password with transaction
      function saveUserAndPassword(cb) {
        we.db.defaultConnection.transaction( (t)=> {
          // create the user
          return we.db.models.user.create(
            req.body, { transaction: t }
          )
          .then( (u)=> {
            newUser = u;
            // save password
            return we.db.models.password.create({
              userId: u.id,
              password: req.body.password,
              confirmPassword: req.body.confirmPassword
            }, { transaction: t });
          });
        })
        .then( ()=> {
          we.log.info( 'Auth plugin:New user:', req.body.email , 'username:' , req.body.username , 'ID:' , newUser.id );
          cb();

          return null;
        })
        .catch( (err)=> {
          cb(err);
          return null;
        });
      }
    ], function afterCreateUserAndPassword(err) {
      if(err) return res.queryError(err);

      if (requireAccountActivation) {
        return we.db.models.authtoken
        .create({
          userId: newUser.id, redirectUrl: res.locals.redirectTo
        })
        .then( (token)=> {

          if (we.plugins['we-plugin-email'] && newUser && newUser.toJSON) {
            const templateVariables = newUser.toJSON();

            templateVariables.siteName = we.config.appName;
            templateVariables.email = newUser.email;
            templateVariables.siteUrl = we.config.hostname;
            templateVariables.confirmUrl = we.config.hostname + '/user/'+ newUser.id +'/activate/' + token.token;

            templateVariables.displayName = (
              newUser.displayName || newUser.fullName
            );

            if (we.systemSettings) {
              if (we.systemSettings.siteName) {
                templateVariables.siteName = we.systemSettings.siteName;
              }
            }

            const options = {
              to: newUser.email
            };
            // send email in async
            we.email.sendEmail('AccontActivationEmail',
              options, templateVariables,
            (err)=> {
              if (err) {
                we.log.error('Action:Login sendAccontActivationEmail:', err);
              }
            });
          }

          res.addMessage('warning', {
            text: 'auth.register.require.email.activation',
            vars: {
              email: newUser.email
            }
          }, {
            requireActivation: true,
            email: newUser.email
          });

          res.locals.authToken = token;
          res.locals.newUserCreated = true;
          res.locals.skipRedirect = true;
          return res.created();
        });
      }

      we.auth.logIn(req, res, newUser, (err)=> {
        if (err) {
          we.log.error('logIn error: ', err);
          return res.serverError(err);
        }

        if (req.accepts('html')) {
          return res.goTo( (res.locals.redirectTo || '/') );
        }

        res.locals.newUserCreated = true;
        res.locals.model = 'user';
        res.locals.data = newUser;
        res.created();
      });
    });
  },

  /**
   * Log out current user
   * Beware! this dont run socket.io disconect
   */
  logout(req, res) {
    const we = req.we;

    we.auth.logOut(req, res, (err)=> {
      if (err) we.log.error('Error on logout user', req.id, req.cookie);
      res.goTo('/');
    });
  },
  /**
   * Login API with session and passport-local strategy
   *
   * This action receives the static and JSON request
   */
  login(req, res, next) {
    const we = req.we;

    if (!we.config.passport || !we.config.passport.strategies || !we.config.passport.strategies.local) {
      return res.notFound();
    }

    if (!lt.canLogin(req)) {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

      we.log.warn('AuthController:login:throttle:', ip);
      res.addMessage('warning', {
        text: 'auth.login.throttle.limit'
      });
      lt.onLoginFail(req);
      return res.badRequest();
    }

    const email = req.body.email;

    if (req.method !== 'POST' || req.isAuthenticated()) {
      // else show login page
      return res.ok();
    }
    // --  set req.body for error page
    res.locals.data = req.body;

    return we.passport.authenticate('local', (err, user, info)=> {
      if (err) {
        lt.onLoginFail(req);
        we.log.error('AuthController:login:Error on get user ', err, email);
        return res.serverError(err);
      }

      if (!user) {
        we.log.debug('AuthController:login:User not found', email);
        res.addMessage('warning', {
          text: info.message,
          vars: { email: email }
        });
        lt.onLoginFail(req);
        return res.badRequest();
      }

      if (user.blocked) {
        we.log.warn('auth.user.blocked.on.login', user.id);
        res.addMessage('danger', 'user.blocked');
        return res.goTo('/');
      }

      if (!user.active) {
        we.log.debug('AuthController:login:User not active', email);
        res.addMessage('warning', {
          text: 'auth.login.user.not.active',
          vars: { email: email }
        });
        return res.badRequest();
      }

      we.auth.logIn(req, res, user, (err)=> {
        if (err) return res.serverError(err);
        we.log.info('AuthController:login: user autheticated:', user.id, user.username);

        if (err) {
          we.log.error('logIn error: ', err);
          return res.serverError(err);
        }

        lt.onLoginSuccess(req);

        res.locals.newUserCreated = true;
        // redirect if are a html response or have the redirectTo
        if (res.locals.redirectTo) return res.goTo(res.locals.redirectTo);
        if (req.accepts('html')) return res.goTo('/');

        res.send({ user: user});
      });
    })(req, res, next);
  },

  /**
   * Activate a user account with activation code
   */
  activate(req, res) {
    const we = req.we;

    const user = {};
    user.id = req.params.id;
    const token = req.params.token;

    function responseForbiden() {
      res.addMessage('warning', 'auth.access.invalid.token');
      return res.goTo('/login');
    }

    we.db.models.authtoken
    .validAuthToken(user.id, token, (err, result, authToken)=> {
      if (err) {
        we.log.error('auth:activate: Error on validate token: ', err, token, user.id);
        return responseForbiden();
      }

      // token is invalid
      if (!result) {
        we.log.info('auth:activate: invalid token: ', token, user.id);
        return responseForbiden();
      }

      // token is valid then get user form db
      we.db.models.user
      .findById(user.id)
      .then( (usr)=> {
        // user found
        if (!usr) {
          we.log.error('auth:activate: user not found: ', user.id);
          // user not found
          return res.badRequest();
        }

        if (usr.blocked) {
          we.log.warn('auth.user.blocked.on.activate', usr.id);
          res.addMessage('danger', 'user.blocked');
          return res.goTo('/');
        }

        // activate user and login
        usr.active = true;

        return usr.save()
        .then( ()=> {
          const rediredtUrl = ( authToken.redirectUrl || '/' );
          // destroy auth token after use
          authToken
          .destroy()
          .catch( (err)=> {
            if (err) we.log.error('Error on delete token', err);
          });
          // login and redirect the user
          we.auth.logIn(req, res, usr, (err)=> {
            if (err) {
              we.log.error('logIn error:', err);
              return res.serverError(err);
            }

            lt.onLoginSuccess(req);

            return res.goTo(rediredtUrl);
          });

          return null;
        })
      })
      .catch(res.queryError);
    });
  },

  /**
   * Forgot password API endpoint
   * Generate one time reset token and send to user email
   */
  forgotPassword(req, res) {
    const we = req.we,
      email = req.body.email;

    res.locals.emailSend = false;
    res.locals.messages = [];
    res.locals.user = req.body.user;

    if (req.method !== 'POST') return res.ok();

    if (!res.locals.user) res.locals.user = {};
    res.locals.formAction = '/auth/forgot-password';

    if (!email) {
      return res.badRequest('auth.forgot-password.field.email.required');
    }

    we.db.models.user
    .find({ where: { email: email }})
    .then( (user)=> {
      if (!user) {
        return res.badRequest('auth.forgot-password.user.not-found', user.id);
      }

      if (user.blocked) {
        we.log.warn('auth.user.blocked.on.forgotPassword', user.id);
        return res.badRequest('auth.forgot-password.user.not-found', user.id);
      }

      we.db.models.authtoken
      .create({
        userId: user.id, tokenType: 'resetPassword'
      })
      .nodeify( (err, token)=> {
        if (err) return res.queryError(err)

        if (we.plugins['we-plugin-email']) {
          const options = {
            to: user.email
          };

          user = user.toJSON();

          if (!user.displayName) {
            user.displayName = user.username;
          }

          const templateVariables = {
            name: user.username,
            displayName: (user.displayName || user.fullName),
            siteName: we.config.appName,
            siteUrl: we.config.hostname,
            resetPasswordUrl: token.getResetUrl()
          };

          if (we.systemSettings) {
            if (we.systemSettings.siteName) {
              templateVariables.siteName = we.systemSettings.siteName;
            }
          }

          we.email
          .sendEmail('AuthResetPasswordEmail', options, templateVariables, (err , emailResp)=> {
            if (err) {
              we.log.error('Error on send email AuthResetPasswordEmail', err, emailResp)
              return res.serverError()
            }
            we.log.verbose('AuthResetPasswordEmail: Email resp:', emailResp)
          });

          res.locals.emailSend = true
        }

        res.addMessage('success', 'auth.forgot-password.email.send');
        res.ok();
      });

      return null;
    })
    .catch(res.queryError)
  },

  /**
   * Generate and return one auth token
   * Only allow admin users in permissions
   */
  authToken(req, res) {
    if (!req.isAuthenticated()) return res.forbiden();

    const we = req.we,
      email = req.params.email;

    if (!email) {
      return res.badRequest('Email is required to request a password reset token.');
    }

    we.db.models.user
    .find({ where: { email: email }})
    .then( (user)=> {
      if (!user) return res.badRequest('unknow error trying to find a user');

      if (user.blocked) {
        we.log.warn('auth.user.blocked.on.authtoken', user.id);
        res.addMessage('danger', 'user.blocked');
        return res.goTo('/');
      }

      return we.db.models.authtoken
      .create({
        'userId': user.id,
        tokenType: 'resetPassword'
      })
      .then( (token)=> {
        if (!token) {
          return res.serverError('unknow error on create auth token');
        }

        res.json(token.getResetUrl());
        return null;
      })
    })
    .catch(req.queryError);
  },

  /**
   * Api endpoint to check if current user can change the password without old password
   */
  checkIfCanResetPassword(req, res) {
    if(!req.isAuthenticated()) return res.forbidden();

    if (req.session && req.session.resetPassword) {
      res.addMessage('success', 'auth.reset-password.success.can');
      return res.ok();
    }

    res.addMessage('error', 'auth.reset-password.error.forbidden');
    return res.forbidden();
  },

  consumeForgotPasswordToken(req, res, next) {
    const we = req.we,
      uid = req.params.id,
      token = req.params.token;

    if (!uid || !token){
      we.log.info('consumeForgotPasswordToken: Uid of token not found', uid, token);
      return next();
    }

    loadUserAndAuthToken(we, uid, token, (error, user, authToken)=> {
      if (error) {
        we.log.error('AuthController:consumeForgotPasswordToken: Error on loadUserAndAuthToken', error);
        return res.serverError();
      }

      if (!user || !authToken) {
        we.log.warn('consumeForgotPasswordToken: invalid token: ', token, ' for uid: ', uid);

        req.flash('messages',[{
          status: 'warning',
          type: 'updated',
          message: req.__('auth.consumeForgotPasswordToken.token.invalid')
        }]);
        return res.goTo('/auth/forgot-password');
      }

      if (user.blocked) {
        res.addMessage('danger', 'user.blocked');
        return res.goTo('/');
      }

      if (user.active) {
        return respondToUser();
      } else {
        // If user dont are active, change and salve the active status
        user.active = true;
        user.save()
        .then(respondToUser)
        .catch(respondToUser);
      }

      function respondToUser(err) {
        if (err) return res.queryError(err);

        we.auth.logIn(req, res, user, (err)=> {
          if (err) {
            we.log.error('AuthController:consumeForgotPasswordToken:logIn error', err);
            return res.serverError(err);
          }
          // consumes the token
          authToken.isValid = false
          authToken
          .destroy()
          .then( ()=> {
            // set session variable req.session.resetPassword to indicate that there is a new password to be defined
            req.session.resetPassword = true;

            res.goTo( '/auth/' + user.id + '/new-password');

            return null;
          })
          .catch( (err)=> {
            if (err) we.log.error('auth:consumeForgotPasswordToken: Error on destroy token:', err);

            return null;
          })
        })

        return null;
      }
    })
  },

  /**
   * newPassword page
   * Page to set new user password after click in new password link
   */
  newPassword(req, res) {
    // not authenticated
    if (!req.isAuthenticated()) return res.goTo('/auth/forgot-password');

    // check access

    if (req.we.acl.canStatic('manage_users', req.userRoleNames)) {
      // can manage users then can change others users password. Ex administrators
    } else if (
      (req.session && req.session.resetPassword) && // have the resetPassword flag
      (req.params.id != req.user.id) // chaning other user password
    ) {
      req.we.log.warn('auth.newPassword cant change other user password: '+req.params.id+ ' auid: '+req.user.id);
      return res.goTo('/auth/'+req.user.id+'/new-password');
    } else if (!req.session || !req.session.resetPassword) {
      // dont have the resetPassword flag
      req.we.log.warn('auth.newPassword req.session.resetPassword is false, uid: '+req.params.id+' auid: '+req.user.id);
      return res.goTo('/auth/forgot-password');
    }

    const we = req.we;

    if (req.method !== 'POST') return res.ok();

    const newPassword = req.body.newPassword,
      rNewPassword = req.body.rNewPassword,
      userId = req.params.id;

    if ( we.utils._.isEmpty(newPassword) || we.utils._.isEmpty(rNewPassword) )
      return res.badRequest('auth.confirmPassword.and.password.required');

    if (newPassword !== rNewPassword)
      return res.badRequest('auth.newPassword.and.password.diferent');

    we.db.models.user
    .findById(userId)
    .then( (user)=> {
      if (!user) {
        we.log.info('newPassword: User not found', user);
        return res.serverError();
      }
      user
      .updatePassword(newPassword, (err)=> {
        if (err) return res.serverError(err);
        // Reset req.session.resetPassword to indicate that the operation has been completed
        if (req.session) {
          delete req.session.resetPassword;
        }

        res.addMessage('success', 'auth.new-password.set.successfully');
        res.locals.successfully = true;

        res.ok();
        return null;
      });

      return null;
    })
    .catch(res.queryError);
  },

  /**
   * Change authenticated user password
   */
  changePassword(req, res) {
    if(!req.isAuthenticated()) return res.goTo('/');
    const we = req.we;

    if (req.method !== 'POST') return res.ok();

    const oldPassword = req.body.password,
      newPassword = req.body.newPassword,
      rNewPassword = req.body.rNewPassword,
      userId = req.user.id;

    if(!req.isAuthenticated()) {
      return res.badRequest('auth.change-password.forbiden');
    }

    // skip old password if have resetPassword flag in session:
    if (we.config.session && req.session && !req.session.resetPassword) {
      if (!oldPassword)
        return res.badRequest('field.password.required');
    }

    // password fields is required:
    if ( we.utils._.isEmpty(newPassword) || we.utils._.isEmpty(rNewPassword) ) {
      return res.badRequest('field.confirm-password.password.required');
    }

    // password fields is diferent:
    if (newPassword !== rNewPassword) {
      return res.badRequest('field.password.confirm-password.diferent');
    }

    we.db.models.user
    .findById(userId)
    .nodeify( (err, user)=> {
      if (err) return res.queryError(err);

      if (!user) {
        we.log.info('resetPassword: User not found', user);
        return res.badRequest();
      }

      // skip password check if have resetPassord flag active
      if (we.config.session && req.session && req.session.resetPassword) {
        return changePassword();
      } else {
        user.verifyPassword(oldPassword, (err, passwordOk)=> {
          if (!passwordOk) {
            return res.badRequest('field.password.invalid');
          }

          return changePassword();
        });
      }

      function changePassword() {
        // set newPassword and save it for generate the password hash on update
        user.updatePassword(newPassword, (err)=> {
          if(err) {
            we.log.error('Error on save user to update password: ', err);
            return res.serverError(err);
          }
          if (we.config.session && req.session) {
            // Reset req.session.resetPassword to indicate that the operation has been completed
            delete req.session.resetPassword;
          }

          if (we.plugins['we-plugin-email']) {
            const appName = we.config.appName;
            const options = {
              to: user.email
            };

            user = user.toJSON();

            if (!user.displayName) {
              user.displayName = user.username;
            }

            const templateVariables = {
              userame: user.username,
              displayName: (user.displayName || user.fullName),
              siteName: appName,
              siteUrl: we.config.hostname
            };

            if (we.systemSettings) {
              if (we.systemSettings.siteName) {
                templateVariables.siteName = we.systemSettings.siteName;
              }
            }

            we.email.sendEmail('AuthChangePasswordEmail', options, templateVariables, (err , emailResp)=> {
              if (err) {
                we.log.error('Error on send email AuthChangePasswordEmail', err, emailResp);
              }

            });
          }

          res.addMessage('success', 'auth.change-password.success');

          return res.ok();
        })
      }
    })
  }
};

/**
 * Load user and auth token
 * @param  {string}   uid      user id
 * @param  {string}   token    user token
 * @param  {Function} callback    callback(error, user, authToken)
 */
function loadUserAndAuthToken(we, uid, token, callback) {
  return we.db.models.user
  .findById(uid)
  .then( (user)=> {

    if (!user) {
      // user not found
      return callback(null, null, null);
    }

    return we.db.models.authtoken
    .find({
      where: {
        userId: user.id,
        token: token,
        isValid: true
      }
    })
    .then( (authToken)=> {
      if (authToken) {
        callback(null, user, authToken);
      } else {
        callback(null, user, null);
      }

      return null;
    });
  })
  .catch(callback);
}
