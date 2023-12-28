import express from "express";
import dotenv from "dotenv"
import cors from "cors"

import workoutRouter from "./routes/workout.js"
import userRouter from "./routes/user.js"
import connectDB from "./config/connectDB.js"

dotenv.config();
const app = express();

connectDB();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    console.log("Hello from server");
    res.json({msg: "Hello from server"})
})
app.use("/api/workouts", workoutRouter);
app.use("/api/user", userRouter);

app.listen(process.env.PORT, () => {
    console.log("Server started on port " + process.env.PORT);
})