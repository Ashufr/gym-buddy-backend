import mongoose from "mongoose";
import userModel from "../models/userModel.js";
import jwt from "jsonwebtoken";

const createToken = (_id, name) => {
    return jwt.sign({_id: _id, name } , process.env.SECRET, { expiresIn: "3d" });
}

const userSignUp = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const user = await userModel.signUp(name, email, password);
        const token = createToken(user._id , user.name);
        res.status(200).json({name : user.name, token});
    } catch (error) {
        console.log(error);
        res.status(400).json({error: error.message});
    }
};

const userLogin = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await userModel.login(email, password);
        const token = createToken(user._id , user.name);
        res.status(200).json({name :user.name, token});
    } catch (error) {
        res.status(400).json({error: error.message});
    }
};

export default { userLogin, userSignUp };
