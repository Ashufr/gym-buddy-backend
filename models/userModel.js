import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        validate: {
            validator: function (value) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
            },
            message: "Invalid email address format",
        },
    },
    password: {
        type: String,
        required: true,
    },
});

// regular async function used because of the use of 'this' keyword
userSchema.statics.signUp = async function (name, email, password) { 

    if(!name || !email || !password) {
        throw new Error("All fields are required");
    }

    if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
        throw new Error("Invalid email address format");
    }

    if(password.length < 8 || !(/[a-z]/).test(password) || !(/[A-Z]/).test(password) || !(/[0-9]/).test(password) || !((/[!@#$%^&*()\-__+.]/).test(password))) {
        throw new Error("Password not Strong enough");
    }
    
    const exists = await this.findOne({ email });
    if (exists) {
        throw new Error("Email already exists");
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await this.create({ name, email, password: hashedPassword });
    return user;
};

userSchema.statics.login = async function (email, password) {
    if (!email || !password) {
        throw new Error("All fields are required");
    }
    const user = await this.findOne({ email });
    if (!user) {
        throw new Error("No such user exists");
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        throw new Error("Incorrect password");
    }
    return user;
}

const userModel = mongoose.model("user", userSchema);
export default userModel;
