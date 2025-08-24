import { Router } from "express";
import { login, logout, registerUser, refreshToken, changeCurrentPassword, getcurrentUser, updateUser, updateUserAvatar, updateCoverImage, getChannelProfile, getWatchHistory } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";


const userRouter = Router();

userRouter.route("/register").post(
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
    registerUser)

userRouter.route("/login").post(login);

// secure routes
userRouter.route("/logout").post(verifyJWT, logout)
userRouter.route("/refresh-token").post(refreshToken)
userRouter.route("/change-password").post(verifyJWT, changeCurrentPassword)
userRouter.route("/current-user").get(verifyJWT, getcurrentUser)
userRouter.route("/update-account").patch(verifyJWT, updateUser)
userRouter.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)
userRouter.route("/cover-image").patch(verifyJWT, upload.single("coverImage"), updateCoverImage)
userRouter.route("/channel/:username").get(verifyJWT, getChannelProfile);
userRouter.route("/watch-history").get(verifyJWT, getWatchHistory);






export default userRouter