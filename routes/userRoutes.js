const express = require("express");
const {
  registerController,
  loginController,
  requireSingIn,
  updateUserController,
} = require("../controllers/userController");

const router = express.Router();

router.post("/register", registerController);
router.post("/login", loginController);

//UPDATE || PUT
router.put("/update-user", requireSingIn, updateUserController);

module.exports = router;
