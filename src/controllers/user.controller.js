
import { asyncHandler } from "../utills/asyncHandler.js";
import { ApiError } from "../utills/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadCloudinary } from "../utills/cloudnary.js";
import { ApiResponse } from "../utills/ApiResponse.js";
import jwt from "jsonwebtoken"


const generateAccessAndRereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        if (!user) {
            throw new ApiError(404, "User not found while generating tokens");
        }
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken }
    }
    catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
}

// register controller
export const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend 
    // validation - not empty
    // check if user already exists or not:username or email
    // check for images or avatar
    // upload them to cloudary ,avatar
    // create user object - create user entry in db
    // remove password and refresh token field from response 
    // check for user creation 
    // return response 

    const { fullName, email, username, password } = req.body

    // check if fields are empty
    if ([fullName, username, email, password].some((field => !field.trim()))) {
        throw new ApiError(400, "All fields are required")
    }

    // check if user exists 
    const existingUser = await User.findOne({
        $or: [{ username: username.toLowerCase() }, { email }]
    })


    if (existingUser) {
        throw new ApiError(409, "User already exists")
    }

    // check if we are getting files or not 
    const avatarLocalPath = req.files?.avatar[0]?.path
    const coverImageLocalPath = req.files?.coverImage[0]?.path
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    // upload image on cloudinary
    const avatar = await uploadCloudinary(avatarLocalPath)
    const coverImage = await uploadCloudinary(coverImageLocalPath)
    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.secure_url,
        coverImage: coverImage?.secure_url,
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(new ApiResponse(201, createdUser, "User registered Successfully"))


})

// login controller 

export const login = asyncHandler(async (req, res) => {
    // get data from request body
    // user or password field is empty
    // find user exist or not 
    // verified password
    // access and refresh token
    // send cookies
    // response



    const { username, password, email } = req.body


    if ((!username && !email) || !password) {
        throw new ApiError(400, "Username/Email and password are required");
    }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

    const { accessToken, refreshToken } = await generateAccessAndRereshTokens(user._id)

    const loggedInuser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(new ApiResponse(200, { user: loggedInuser, accessToken, refreshToken }, "User logged In Successfully"))

})


export const refreshToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken
    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized - No refresh token provided")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findById(decodedToken._id)

        if (!user) {
            throw new ApiError(401, "Invalid refresh token - user not found")
        }
        if (incomingRefreshToken != user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
        }

        const { accessToken, refreshToken } = await generateAccessAndRereshTokens(user._id);
        const options = {
            httpOnly: true,
            secure: true
        }

        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(new ApiResponse(200, { accessToken, refreshToken }, "Access token refreshed sucessfully"))
    }

    catch (error) {
        throw new ApiError(401, error?.message || "Invalid or expired refresh token")
    }



})

export const logout = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                refreshToken: undefined
            },
        }, {
        new: true
    }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    res.status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options).json(new ApiResponse(200, {}, "User logged out successfully"))
})

