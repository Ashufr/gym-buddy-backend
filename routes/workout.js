import express from "express"

import workoutController from "../controllers/workoutController.js";
import requireAuth from "../middleware/requireAuth.js";

const {getAllWorkouts, getWorkout, createWorkout, updateWorkout, deleteWorkout} = workoutController

const router = express.Router();

//Middleware for all routes
router.use(requireAuth);

router.get("/", getAllWorkouts)
.get("/:id", getWorkout)
.post("/", createWorkout)
.patch("/:id", updateWorkout)
.delete("/:id", deleteWorkout);

export default router;

