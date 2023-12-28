import mongoose from "mongoose";

const connectDB = async () => {
    try {
        // console.log(process.env.PORT);
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(`MongoDB connected: ${conn.connection.host}`);
    } catch (error) {
        console.log(error);
        console.log("MongoDB connection failed");
        process.exit(1);
    }
}
// connectDB();

export default connectDB;