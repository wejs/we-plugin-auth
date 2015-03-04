/**
 * Modal para ações do sistema que necessitam que o usuário esteja autenticado 
 */

App.WeAuthModalNeedLoginComponent = Ember.Component.extend({
  auth: function() {
    return App.get('auth');
  }.property('App.auth'),

  actions: {
    logRegister: function () {
      this.get('auth').registerUser();
    },

    logIn: function () {
      this.get('auth').authenticate();
    },  	
  }
});
