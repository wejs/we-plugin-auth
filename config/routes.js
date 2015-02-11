/**
 * (1) Core middleware
 *
 * Middleware included with `app.use` is run first, before the router
 */


/**
 * (2) Static routes
 *
 * This object routes static URLs to handler functions--
 * In most cases, these functions are actions inside of your controllers.
 * For convenience, you can also connect routes directly to views or external URLs.
 *
 */

module.exports.routes = {
  'get /account': 'AuthController.current',

  // update authenticated user
  'post /account': {
    controller: 'AuthController',
    action: 'updateAccountData'
  },

  // User Auth
  // TODO move to AuthController

  'get /signup': {
    controller: 'AuthController',
    action: 'signupPage'
  },

  'post /signup': {
    controller: 'AuthController',
    action: 'signup'
    //view: 'users/signup'
  },

  'post /api/v1/signup': {
    controller: 'AuthController',
    action: 'signup'
    //view: 'users/signup'
  },

  // form login
  'get /login': {
    controller: 'AuthController',
    action: 'loginPage'
  },
  // form login / post
  'post /login': {
    controller: 'AuthController',
    action: 'login'
  },

  // api login
  'post /auth/login': {
    controller    : 'AuthController',
    action        : 'login'
  },

  '/auth/logout': {
    controller    : 'AuthController',
    action        : 'logout'
  },

  // form to get one time login email
  'get /auth/forgot-password': {
    controller    : 'AuthController',
    action        : 'forgotPasswordPage'
  },

  // post for get new password link
  'post /auth/forgot-password': {
    controller    : 'AuthController',
    action        : 'forgotPassword'
  },

  '/auth/:uid/reset-password/:token': {
    controller: 'AuthController',
    action: 'consumeForgotPasswordToken'
  },

  // new password
  'post /auth/new-password':{
    controller    : 'AuthController',
    action        : 'newPassword'
  },
  'get /auth/:id/new-password':{
    controller    : 'AuthController',
    action        : 'newPasswordPage'
  },  

  // change password
  'post /change-password':{
    controller    : 'AuthController',
    action        : 'changePassword'
  },
  'get /change-password':{
    controller    : 'AuthController',
    action        : 'changePasswordPage'
  },

  'get /api/v1/auth/callback/:access_token?':{
    controller    : 'AuthController',
    action        : 'oauth2Callback'
  },

  'get /user/:id/activate/:token':{
    controller    : 'AuthController',
    action        : 'activate'
  },

  'post /auth/auth-token':{
    controller    : 'AuthController',
    action        : 'authToken'
  }
}