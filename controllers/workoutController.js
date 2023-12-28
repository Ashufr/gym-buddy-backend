import mongoose from "mongoose";
import workoutModel from "../models/workoutModel.js";

const getAllWorkouts = async (req, res) => {
    const user_id = req.user._id
    try {
        const workouts = await workoutModel.find({ user_id}).sort({createdAt: -1});
        res.status(200).json(workouts);
    } catch (error) {
        res.status(400).json(error);
        console.log(error)
    }
}

const getWorkout = async (req, res) => {
    const {id} = req.params;

    if(!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(404).json({error: "invalid id"});
    }
    try {
        const workout = await workoutModel.findById(id);
        if(!workout) return res.status(404).json({error: "No such workout"});
        res.status(200).json(workout);
    } catch (error) {
        res.status(400).json(error);
        console.log(error)
    }
}

const createWorkout = async (req, res) => {
    const {title, reps, load} = req.body;
    const user_id = req.user._id
    const emptyFields = [];

    if(!title) {
        emptyFields.push("title");
    }
    if(!reps) {
        emptyFields.push("reps");
    }
    if(!load) {
        emptyFields.push("load");
    }
    if(emptyFields.length > 0) {
        return res.status(400).json({error: "Please fill in all the fields", emptyFields});
    }

    try {
        const workout = await workoutModel.create({title, reps, load , user_id});
        res.status(200).json(workout);
    } catch (error) {
        res.status(400).json({error : error.message});
        console.log(error)
    }
}

const updateWorkout = async (req, res) => {
    const {id} = req.params;
    
    if(!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(404).json({error: "invalid id"});
    }
    try {
        const workout = await workoutModel.findByIdAndUpdate(id, req.body, {new: true}); // new sends the updated data in json
        if(!workout) return res.status(404).json({error: "No such workout"});
        res.status(200).json(workout);
    } catch (error) {
        res.status(400).json(error);
        console.log(error)
    }
}

const deleteWorkout = async (req, res) => {
    const {id} = req.params;
    
    if(!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(404).json({error: "invalid id"});
    }
    try {
        const workout = await workoutModel.findByIdAndDelete(id);
        if(!workout) return res.status(404).json({error: "No such workout"});
        res.status(200).json(workout);
    } catch(error){
        res.status(400).json(error);
        console.log(error)
    }
}

export default {getAllWorkouts, getWorkout, createWorkout, updateWorkout, deleteWorkout};