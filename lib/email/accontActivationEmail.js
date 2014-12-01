module.exports = function sendAccontActivationEmail(user, siteBaseUrl,sails, cb){
  sails.models.authtoken.create({ 'userId': user.id })
  .exec(function (error, token) {
    if(error) return cb(error);
    var options = {};
    // to email
    options.email = user.email;
    // fetch user data after set tempalteVariables
    if(user.toJSON) user = user.toJSON();

    var templateVariables = {
      user: user,
      site: {
        name: sails.config.appName,
        url: sails.config.hostname
      },
      confirmUrl: siteBaseUrl + '/user/'+ user.id +'/activate/' + token.token
    };

    var templateName = 'AccontActivationEmail';

    //sails.config.appName + 'We.js -> Register validation email.';
    // get locale
    var locale = user.language;
    if (!locale) locale = sails.config.i18n.defaultLocale;

    options.subject = sails.__({
      phrase: 'we.email.AccontActivationEmail.subject',
      locale: locale
    },
      templateVariables
    );

    sails.email.sendEmail(options ,templateName ,templateVariables, cb);
  });
};