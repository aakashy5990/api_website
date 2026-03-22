const express = require("express");
const { restrictToLoggedinUserOnly } = require("../middlewares/auth");
const { getnusers } = require("../controllers/externalapi");

const router = express.Router();

//authentication middleware to all external API routes
router.use(restrictToLoggedinUserOnly);

// Route to render the external API page with data
router.get('/', getnusers);

router.get('/nusers', getnusers)

module.exports = router;