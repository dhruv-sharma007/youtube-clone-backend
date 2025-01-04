import mongoose from "mongoose";
import { DB_Name } from "./constants.js";












/*
import express from "express"
const app = express()

(async () => {
    try {
        await mongoose.connect(`${process.env.MONGO_URI}/${DB_Name}`)
        app.on("error", (err) => {
            console.log("Mongodb not connected ERROR: ",err)
        })

        app.listen(process.env.PORT, () => {
            console.log(`Server is running on  http://localhost:${process.env.PORT}`)
        })

    }catch (error) {
        console.log("ERROR: ",error)
        throw error
    }
})()
    */