import { asyncHandler } from "../utils/AsyncHandler.js";


const registerUser = asyncHandler(async (req, res) => {
    return res.status(200).json({ 
        message: "ok" 
    })
    }
)

export { registerUser };