import { Router } from "express";
import {     
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    ChangeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory   
    } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

//user Authentication routes
router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser
);
router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWT, logoutUser)
router.route("refresh-token").post(refreshAccessToken)

//User Profile Updates Routes
router.route("/change-password").post(verifyJWT, ChangeCurrentPassword)
router.route("/update-account-details").patch(verifyJWT, updateAccountDetails)
router.route("/update-user-avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)
router.route("/update-user-coverImage").patch(verifyJWT, upload.single("coverImage"), updateUserCoverImage)

//user profile routes
router.route("/current-user").get(verifyJWT, getCurrentUser)
router.route("/watch-history").get(verifyJWT, getWatchHistory)

//channel profile routes
router.route("/c/:username").get(verifyJWT, getUserChannelProfile)


export default router