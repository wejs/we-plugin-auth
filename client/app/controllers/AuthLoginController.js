
(function($, we, Ember, App){

  App.AuthLoginController = Ember.ObjectController.extend({
    emailPlaceholder: 'Email address',
    passwordPlaceholder: 'Password',
    messages: [],
    loginUrl: 'http://accounts.wejs.org/auth/login',
    init: function init(){
      this._super();
      this.set('loginUrl',we.configs.server.providers.accounts+'/auth/login');
    },
    actions: {
      //Submit the modal
      login: function() {
        var _this = this;
        $.post( this.get('loginUrl') ,{
          email: this.get('email'),
          password: this.get('password')
        })
        .done(function(data) {
          if(data.id){
            location.reload();
          }
        })
        .fail(function(data) {
          if(data.responseText){
            var responseJSON = jQuery.parseJSON(data.responseText);
            _this.set('messages', [{
              status: 'danger',
              message: responseJSON.error[0].message
            }]);
          }else{
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

})(jQuery, we, Ember, App);