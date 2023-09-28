const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email!'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email address']
  },
  photo: String,
  password: {
    type: String,
    require: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    requires: [true, 'Please confirm your password'],
    validate: {
      //this only works on CREATE AND  SAVE!!
      validator: function (el) {
        return el === this.password;
      },
      message: 'Password are not the same'
    }
  },
  passwordChangedAt: Date
});
//this middleware runs between the data we get and store in database
userSchema.pre('save', async function (next) {
  //Only run this function if password was actually modified
  if (!this.isModified('password')) return next();
  //Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);
  //Delete the passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});
//this below function is used to check the encrypted password is crt or not by using the bcrypt funtion to check both encrypted on
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return bcrypt.compare(candidatePassword, userPassword);
};
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    //   const changedTimestamp = parseInt(
    //     this.passwordChangedAt.getTime() / 1000,
    //     10
    //   );
    //   //if the user has not changed their password then it will return false
    console.log(this.passwordChangedAt, JWTTimestamp);
    // return JWTTimestamp < changedTimestamp;
  }
  //if the token was changed before the issue time then it will be false
  return false; //100<200
};

const User = mongoose.model('User', userSchema);
module.exports = User;
