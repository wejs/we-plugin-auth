module.exports = function uliCommand(program, helpers) {
  /**
   * Get one time login link for one user by user id
   */
  let we;

  program
  .command('uli [id]')
  .description('Get one time login url')
  .option('-C, --console', 'Use console.log to output auth url')
  .action(function run(opts) {
    we = helpers.getWe();

    we.bootstrap( (err, we)=> {
      if (err) return doneAll(err);

      const uid = process.argv[3];
      if (! Number(uid) ) return doneAll('Invalid Uid');

      we.db.models.user.findOne({ where: { id : uid} })
      .then( (user)=> {
        return we.db.models.authtoken
        .create({
          'userId': user.id,
          tokenType: 'resetPassword'
        })
        .then( (token)=> {
          if (!token) {
            doneAll('unknow error on create auth token');
          } else {
            if (!opts.console) {
              console.log('resetUrl>>', { token: token.getResetUrl() });
            } else {
              // default
              we.log.info('resetUrl>>', { token: token.getResetUrl() });
            }

            doneAll();
          }
        });
      })
      .catch(doneAll);
    });

    function doneAll(err) {
      if ( err ) {
        we.log.error('Error get user login link', {
          errro: err
        });
      }
      // end / exit
      process.exit();
    }
  });
}