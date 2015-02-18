
(function($, Ember, App){

  App.Router.map(function() {
    // auth
    this.route('authForgotPassword',{path: '/auth/forgot-password'});
    this.route('authResetPasswordToken',{path: '/auth/reset-password/:token_id'});
    this.route('authChangePassword',{path: '/auth/change-password/'});
    this.route('authRegister',{path: '/signup'});

    this.route('authLogin',{path: '/login'});
  });

  App.AuthLoginRoute = Ember.Route.extend(App.UnAuthenticatedRouteMixin);

  App.AuthResetPasswordTokenRoute = Ember.Route.extend({
    renderTemplate: function() {
      this.render('auth/ResetPasswordToken');
    },
    model: function(params) {
      return {
        user: App.currentUser,
        tokenid: params['token_id']
      };
    }
  });

  App.AuthChangePasswordRoute = Ember.Route.extend({
    renderTemplate: function() {
      this.render('auth/ChangePassword');
    },
    model: function() {
      return {
        user: { 'password':'', 'oldpassword':'', 'repeatpassword':'' }
      };
    }
  });

  App.AuthForgotPasswordRoute = Ember.Route.extend({
    renderTemplate: function() {
      this.render('auth/ForgotPassword');
    },
    model: function() {
      return {
        email: '',
        messages: [],
      };
    }
  });

  App.AuthRegisterRoute = Ember.Route.extend(App.UnAuthenticatedRouteMixin, {
    beforeModel: function (transition, queryParams) {
      this._super(transition, queryParams);
    },
    renderTemplate: function() {
      this.render('auth/RegisterForm');
    },
    controllerName: 'AuthRegister'
  });


})(jQuery, Ember, App);