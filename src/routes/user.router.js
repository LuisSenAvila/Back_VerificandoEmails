const { getAll, create, getOne, remove, update, verified, login, logget, resetPassword, reset_passwordCode } = require('../controllers/user.controller');
const express = require('express');
const { verifyJWT } = require('../utils/verifyJWT');

const routerUser = express.Router();

routerUser.route('/')
    .get(verifyJWT,getAll)
    .post(create);
routerUser.route('/login')
    .post(login)
routerUser.route('/me')
    .get(verifyJWT,logget)
routerUser.route('/reset_password')
    .post(resetPassword)
routerUser.route('/verify/:code')
    .get(verified)

routerUser.route('/:id')
    .get(verifyJWT,getOne)
    .delete(verifyJWT,remove)
    .put(verifyJWT,update);
routerUser.route('/reset_password/:code')
    .post(reset_passwordCode)

module.exports = routerUser;