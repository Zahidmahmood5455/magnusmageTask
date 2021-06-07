const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../model/userModel');
const sendEmail = require('../utils/email')

const signToken = (id) =>
  jwt.sign({ id }, 'zahidmahmood-224-computerscience', {
    expiresIn: '90d',
  });

const createSendJWt = (user, statusCode, req, res) => {
  const jwtToken = signToken(user._id);

  res.cookie('jwt', jwtToken, {
    expires: new Date(
      Date.now() + 90 * 24 * 60 * 60 * 1000
    ),
  });

  res.status(statusCode).json({
    status: 'success',
    jwtToken,
    data: {
      user: user,
    },
  });
};

exports.signup = async (req, res, next) => {
    //1) Create User/signup user
    try {
        const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm,
        });
        console.log(2);
        res.status(200).json({
            status: 'success',
            data: {
                data: newUser,
            },
        });

    } catch (err) {
            res.status(201).json({
            status: 'fail',
            message: err.message
        });
    }
} 

exports.login = async (req, res, next) => {
    const { email, password } = req.body;
  
    //1) check email && password its there
    if (!email && password) {
      return next(new Error('Please Enter Email and Password!'));
    }
  
    //2)check user exist and verify password
    const currentUser = await User.findOne({ email }).select('+password');
  
    if ( !currentUser || !(await currentUser.passwordCorrect(currentUser.password, password))) {
    //   console.log('Incorrect email and password');
      return next(new Error('Incorrect email and password'));
    }
 
  const token = currentUser.createloginToken();
  await currentUser.save({ validateBeforeSave: false });
  const message = `your login token is ${token}`;
  try{
    await sendEmail({
      email: currentUser.email,
      subject: 'Your Login token (Valid for 10 minutes)',
      message,
    });
  } catch (err) {
    currentUser.loginToken = undefined;
    currentUser.loginTokenExpires = undefined;
    await currentUser.save({ validateBeforeSave: false });
    console.log('Email not send.Try again!');
    return next();
  }

  res.status(200).json({
    status: 'success',
    message: 'Token send to email',
  });
};

exports.verifyToken = async (req, res, next) => {
    //1) For Find user based on token, First encrypt that token
    //console.log(req.params.token);
    console.log(2);
    const hashtoken = crypto
      .createHash('sha256')
      .update(req.body.token)
      .digest('hex');
    //console.log(hashtoken);
    const user = await User.findOne({
      loginToken: hashtoken,
      loginTokenExpires: { $gt: Date.now() },
    });
    //console.log(user);
    if (!user) {
        // console.log('Invalid token or expires Token!')
        return next(new Error('Invalid token or expires Token!'));
    }
  
    user.loginToken = undefined;
    user.loginTokenExpires = undefined;
    await user.save({ validateBeforeSave: false });
  
    //3) Create JWT and send res with JWT to user
    createSendJWt(user, 200, req, res);
  };

exports.protect = async (req, res, next) => {
    //1) check header its there
    let token;
    if ( req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    if (!token) {
    //   console.log('You are not logged in!');
      return next(new Error('You are not logged in!'));
    }
    //2) Verification of JWT
    const decoded = await promisify(jwt.verify)(token, 'zahidmahmood-224-computerscience');
    //3) Check That user currently exist or not
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
    //   console.log('Token not belonging to that user.');
      return next(new Error('Token not belonging to that user.'));
    }  
    
    //5) Grant Access
    req.user = currentUser;
    next();
  };
  