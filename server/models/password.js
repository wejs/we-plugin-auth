/**
 * Password model
 *
 * @module      :: Model
 * @description :: Model used to store user passwords
 */

const path = require('path'),
  // load one of the bcript libs, install C version of the bcript lib in project
  bcrypt = getBcryptLib();

const newPasswordValidation = {
  /**
   * Password can not be empty on create
   *
   * @param  {String} val
   */
  notEmptyOnCreate(val) {
    if (this.isNewRecord) {
      if (!val) {
        throw new Error('auth.register.confirmPassword.required');
      }
    }
  },
  /**
   * Check if confirm and newPassword are equal:
   *
   * @param  {String} val
   */
  equalPasswordFields(val) {
    if (this.isNewRecord) {
      if (this.getDataValue('password') != val) {
        throw new Error('auth.confirmPassword.and.newPassword.diferent');
      }
    }
  }
};

module.exports = function Model(we) {
  // Password model:
  return {
    definition: {
      userId : { type: we.db.Sequelize.BIGINT },
      active : { type: we.db.Sequelize.BOOLEAN, defaultValue: true },

      password    : {
        type: we.db.Sequelize.TEXT,
        validate: newPasswordValidation
      },
      confirmPassword: {
        type: we.db.Sequelize.VIRTUAL,
        set(val) {
          this.setDataValue('confirmPassword', val);
        },
        validate: newPasswordValidation
      }
    },

    options: {

      SALT_WORK_FACTOR: 10,

      enableAlias: false,
      classMethods: {
        /**
         * async password generation
         *
         * @param  {string}   password
         * @param  {Function} next     callback
         */
        generatePassword(password, next) {
          const SALT_WORK_FACTOR = this.options.SALT_WORK_FACTOR;

          return bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
            return bcrypt.hash(password, salt, next);
          });
        },

        /**
         * Verify user password
         *
         * @param  {string}   password user password string to test
         * @param  {string}   hash     DB user hased password
         * @param  {Function} cb       Optional callback
         * @return {boolean}           return true or false if no callback is passed
         */
        verifyPassword(password, hash, cb) {
          // if user dont have a password
          if (!hash) {
            if(!cb) return false;
            return cb(null, false);
          }

          // if dont has a callback do a sync check
          if (!cb) return bcrypt.compareSync(password, hash);
          // else compare async
          bcrypt.compare(password, hash, cb);
        }
      },

      instanceMethods: {
        /**
         * Verify one password:
         *
         * @param  {string}   password string to verify
         * @param  {Function} next     callback
         */
        validatePassword(password, next) {
          bcrypt.compare(password, this.password, next);
        },
        toJSON() {
          return this.get();
        }
      },
      hooks: {
        // - Lifecycle Callbacks

        /**
         * Before create one record
         *
         * @param  {Object}   record  record data
         * @param  {Object}   options sequelize options
         * @param  {Function} next    callback
         */
        beforeCreate(record, options, next) {
          this.generatePassword(record.password, (err, hash)=> {
            if (err) return next(err);
            record.password = hash;
            // remove old user paswords on create an new one:
            we.db.models.password
            .destroy({
              where: { userId: record.userId }
            })
            .nodeify( (err, result)=> {
              next(err, result);
              return null;
            });
          });
        },
        /**
         * Before update record
         *
         * @param  {Object}   record  sequelize record to be updated
         * @param  {Object}   options sequeslize options
         * @param  {Function} next    callback
         */
        beforeUpdate(record, options, next) {
          // generate an new hash on every update of the password record:
          this.generatePassword(record.password, (err, hash)=> {
            if (err) return next(err);
            record.password = hash;
            next(null, record);
            return null;
          });
        },
      }
    }
  };
}

/**
 * Get bcrypt lib
 *
 * Method to get C version of bcrypt or fallback to slower JS version
 *
 * @return {Object} Bcrypt lib
 */
function getBcryptLib() {
  try {
    // try to load bcrypt from project:
    return require( path.join(process.pwd(), 'node_modules', 'bcrypt') );
  } catch(e) {
    return require('bcryptjs');
  }
}
