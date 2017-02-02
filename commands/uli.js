module.exports = function uliCommand(program, helpers) {
  /**
   * Get one time login link for one user by user id
   */
  let we;

  program
  .command('uli [id]')
  .description('Get one time login url')
  .action(function run() {
    we = helpers.getWe();

    we.bootstrap( (err, we)=> {
      if (err) return doneAll(err);

      const uid = process.argv[3];
      if (! Number(uid) ) return doneAll('Invalid Uid');

      we.db.models.user.findById(uid)
      .then( (user)=> {
        we.db.models.authtoken
        .create({
          'userId': user.id,
          tokenType: 'resetPassword'
        })
        .then( (token)=> {
          if (!token) {
            doneAll('unknow error on create auth token');
          } else {
            we.log.info('resetUrl>>', token.getResetUrl());
            doneAll();
          }
          return null;
        });

        return null;
      });
    });

    function doneAll(err) {
      if ( err ) {
        we.log.error('Error get user login link', err);
      }
      // end / exit
      process.exit();
      return null;
    }
  });
}