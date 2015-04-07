module.exports.auth = {
  landingPage: 'https://cursos.atencaobasica.org.br',
  callLandingPage: function (landingPage, req, res, next) {
    return res.redirect(landingPage);
  }
}
