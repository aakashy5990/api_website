const express = require("express");
const { restrictToLoggedinUserOnly } = require("../middlewares/auth");
const { getusers,getuserbyid } = require("../controllers/internalapi");

const router = express.Router();

// Add authentication middleware to all internal API routes

// this give the auth on postman because i don't know how i use header on postman or where i do mistake so temprory i comment the code 


// router.use(restrictToLoggedinUserOnly);

router.get('/api/users', getusers);

router.get('/api/users/:id', getuserbyid);

module.exports = router;