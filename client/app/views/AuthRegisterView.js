
(function($, Ember, App){


/*
  App.AuthRegisterView = Ember.View.extend({
    user: {},

    templateName: 'auth/registerForm',
    isVisible: true,

    defaultlanguages: ['en-us', 'pt-br'],
    emailPlaceholder: we.i18n('Your email'),
    passwordPlaceholder: we.i18n('Password'),
    confirmPasswordPlaceholder: we.i18n('Confirm password'),
    usernamePlaceholder: we.i18n('Pick a username'),

    init: function(){
      this._super();
      var self = this;

      if(we.authenticatedUser.id){
        this.set('isVisible', false);
      }

      we.hooks.on("user-authenticated",function(user, done){
        self.set('isVisible', false);
        done();
      });

      we.hooks.on("user-unauthenticated",function(user, done){
        self.set('isVisible', true);
        done();
      });
    },
    actions: {
      submit: function() {
        var user = this.get('user');

        console.warn(user);
        return '';
        $.post('/signup',user)
        .done(function(data) {
          console.log('data',data);
          if(data.id){
            we.authenticatedUser = data;
            we.hooks.trigger("user-authenticated", {
              'user':  data
            });
          }
        })
        .fail(function(data) {
          console.error( "Error on login", data );
        });
      }
    }
  });
*/

})(jQuery, Ember, App);
