const express = require('express');
const passport = require('passport');
const router = express.Router();

const reviewController = require('../controller/reviewController');

router.post(
    '/create-review/:id',
    passport.checkAuthentication,
    reviewController.createReview
);

module.exports = router;