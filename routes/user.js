import express from "express";
import userController from "../controllers/userController.js";

const router = express.Router();
const { userLogin, userSignUp } = userController

router.post("/signup", userSignUp)
.post("/login", userLogin)

export default router