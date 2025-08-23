import { Router } from "express";
import { login, logout, registerUser, refreshToken } from "../controllers/user.controller.js";
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


export default userRouter