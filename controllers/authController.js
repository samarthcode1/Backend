const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    //this is used to give the duration when the password is going to expire
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

//JWT--Jason Web Token
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm
  });

  const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    token,
    data: {
      user: newUser
    }
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  //1)Check if email and passwords exits
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  //2)Check if user exits && password is coorect
  const user = await User.findOne({ email }).select('+password');
  //console.log(user);
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  //3) If everything ok,sedn token to client
  const token = signToken(user._id);
  res.status(200).json({
    status: 'success',
    token
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  //1)Getting token and check of its's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  // console.log(token);

  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access', 401)
    );
  }
  //2) Verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET); //to create te test secret
  // console.log(decoded);
  //3)Check if user still exists
  const freshUser = await User.findById(decoded.id);
  if (!freshUser) {
    return next(
      new AppError('The user belonging to this token does not exists', 401)
    );
  }
  //4) If user changed password after the token was issued
  if (freshUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please log in again', 401)
    );
  }
  //GRANT access to PROTECTED ROUTE
  req.user = freshUser; //to put the entire user data to the request
  next(); //next lead us to the next middleware
});
