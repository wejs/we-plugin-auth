App.AuthLoginController = Ember.ObjectController.extend({
  messages: [],
  loginUrl: Ember.computed.alias('App.auth.loginUrl'),

  actions: {
    //Submit the modal
    login: function() {
      NProgress.start();
      NProgress.set(0.5);
      var _this = this;
      $.post( this.get('loginUrl') ,{
        email: this.get('email'),
        password: this.get('password')
      })
      .done(function(data) {
        NProgress.done(true);
        if(data.id){
          location.reload();
        }
      })
      .fail(function(data) {
        NProgress.done(true);

        if (data.responseText) {
          var responseJSON = jQuery.parseJSON(data.responseText);
          console.log('responseJSON', responseJSON);
          _this.set('messages', [{
            status: 'danger',
            message: responseJSON.messages[0].message
          }]);
        } else {
          console.error( 'Error on login',data);
        }
      });
    },
    goToForgotPaswordPage: function(){
      this.get('router').transitionTo('authForgotPassword');
    },

    goToRegisterPage: function(){
      this.get('router').transitionTo('authRegister');
    }
  }
});
