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

    if(!password.match(/^(?=(.*[a-z]){3,})(?=(.*[A-Z]){2,})(?=(.*[0-9]){2,})(?=(.*[!@#$%^&*()\-__+.]){1,}).{8,}$/)){
        throw new Error("Password not Strong enough");
        // ^                               start anchor
        // (?=(.*[a-z]){3,})               lowercase letters. {3,} indicates that you want 3 of this group
        // (?=(.*[A-Z]){2,})               uppercase letters. {2,} indicates that you want 2 of this group
        // (?=(.*[0-9]){2,})               numbers. {2,} indicates that you want 2 of this group
        // (?=(.*[!@#$%^&*()\-__+.]){1,})  all the special characters in the [] fields. The ones used by regex are escaped by using the \ or the character itself. {1,} is redundant, but good practice, in case you change that to more than 1 in the future. Also keeps all the groups consistent
        // {8,}                            indicates that you want 8 or more
        // $                               end anchor
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
