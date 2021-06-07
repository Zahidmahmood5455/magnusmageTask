const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const userSchema = new mongoose.Schema({
    name: {
      type: String,
      required: [true, 'A user must have a name!'],
    },
    email: {
      type: String,
      required: [true, 'A user must have a email!'],
      unique: true,
      validate: [validator.isEmail, 'Invalid email.'],
    },
    password: {
      type: String,
      required: [true, 'A user must have a password!'],
      minlength: 4,
      select: false,
    },
    passwordConfirm: {
      type: String,
      required: [true, 'A user must have a password!'],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: 'Password and confirm Password are not same.',
      },
    },
    loginToken: String,
    loginTokenExpires: Date,
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
    next();
});

userSchema.methods.passwordCorrect = async (originalpassword, newpassword) =>
await bcrypt.compare(newpassword, originalpassword);  

userSchema.methods.createloginToken = function (next) {
    const token = crypto.randomBytes(2).toString('hex');
    this.loginToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    this.loginTokenExpires = Date.now() + 10 * 60 * 1000;
    return token;
};

const User = mongoose.model('User', userSchema);

module.exports = User;