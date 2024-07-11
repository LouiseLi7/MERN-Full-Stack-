const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const HttpError = require('../models/http-error');
const User = require('../models/user');

const getUsers = async (req, res, next) => {
  let users;
  try {
    users = await User.find({}, '-password');
  } catch (err) {
    const error = new HttpError(
      'Fetching users failed, please try again later.',
      500
    );
    return next(error);
  }
  res.json({ users: users.map(user => user.toObject({ getters: true })) });
};

const signup = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(
      new HttpError('Invalid inputs passed, please check your data.', 422)
    );
  }
  const { name, email, password } = req.body;

  let existingUser;
  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError(
      'Signing up failed, please try again later.',
      500
    );
    return next(error);
  }

  if (existingUser) {
    const error = new HttpError(
      'User exists already, please login instead.',
      422
    );
    return next(error);
  }

  let hashedPassword;
  try{
    hashedPassword = await bcrypt.hash(password,12);
  }catch(err){
    const error = new HttpError("could not create user.",500);
    return next(error);
  }

  const createdUser = new User({
    name,
    email,
    image: req.file.path,
    password:hashedPassword,
    places: []
  });

  try {
    await createdUser.save();
  } catch (err) {
    const error = new HttpError(
      'Signing up failed, please try again later.',
      500
    );
    return next(error);
  }

  let token;
  try{
    token = jwt.sign({userId:createdUser.id,email:createdUser.email},
      'supersecret_dont_share',
      {expiresIn:'1h'});
  }catch(err){
    return next(new HttpError("Error in creating tokens",500));
  }

  // res.status(201).json({ user: createdUser.toObject({ getters: true }) });
  res.status(201).json({ user: createdUser.id,email:createdUser.email,token:token});
};

const login = async (req, res, next) => {
  const { email, password } = req.body;

  let existingUser;

  try {
    existingUser = await User.findOne({ email: email });
  } catch (err) {
    const error = new HttpError(
      'Loggin in failed, please try again later.',
      500
    );
    return next(error);
  }

  if (!existingUser) {
    const error = new HttpError(
      'Invalid credentials, could not log you in.',
      401
    );
    return next(error);
  }

  let isValidPassword = false;
  try{
    isValidPassword = await bcrypt.compare(password,existingUser.password);
  }catch(err){
    return next(new HttpError("Something went wrong with credential"),500);
  }

  if(!isValidPassword){
    return next(new HttpError("Wrong password"),500);
  }

  let token;
  try{
    token = jwt.login({userId:existingUser.id,email:existingUser.email},
      'supersecret_dont_share',
      {expiresIn:'1h'});
  }catch(err){
    return next(new HttpError("Error in creating tokens",500));
  }

  // res.status(201).json({ user: createdUser.toObject({ getters: true }) });
  res.status(201).json({ user: existingUser.id,email:existingUser.email,token:token});


  // res.json({
  //   message: 'Logged in!',
  //   user: existingUser.toObject({ getters: true })
  // });
};

exports.getUsers = getUsers;
exports.signup = signup;
exports.login = login;
