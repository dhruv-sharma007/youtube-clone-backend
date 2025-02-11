import { asyncHandler } from "../utils/AsyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import jwt from "jsonwebtoken"

export const verifyJWT = asyncHandler(async(req, res, next) => {
        try {
            const token = req.cookies?.accessToken || req.header ("Authorization").replace("Bearer ", "")
    
            if(!token) {
                throw new Error("You are not authenticated")
            }
    
           const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
            const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
    
            if(!User){
                throw new Error(401,"Invalid Access Token")
            }
    
            req.user = user
            next()
        } catch (error) {
            throw new ApiError(401, error?.message || "Invalid Access Token") 
        }

})