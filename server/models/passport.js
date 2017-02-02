/**
 * passport model
 *
 * @module      :: Model
 * @description :: Model used to store passport auth strategy
 *
 */

module.exports = function Model(we) {
  // set sequelize model define and options
  return {
    definition: {
      // local, google, facebook ...
      protocol: { type: we.db.Sequelize.STRING, allowNull: false },
      accessToken : { type: we.db.Sequelize.STRING },
      provider   : { type: we.db.Sequelize.STRING },
      identifier : { type: we.db.Sequelize.STRING },
      tokens     : { type: we.db.Sequelize.TEXT }
    },
    options: {
      SALT_WORK_FACTOR: 10,
      enableAlias: false
    }
  };
}