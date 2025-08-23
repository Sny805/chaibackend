
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


export const changeCurrentPassword = asyncHandler(async (req, res) => {

    const { oldPassword, newPassword } = req.body

    if (!oldPassword || !newPassword) {
        throw new ApiError(400, "Old password and new password are required")
    }

    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if (!isPasswordCorrect) {
        throw new ApiError(400, "Old password is incorrect")
    }

    user.password = newPassword
    await user.save({ validateBeforeSave: false })

    return res.status(200).json(new ApiResponse(200, {}, "Password changed successfully"))
})


export const getcurrentUser = asyncHandler(async (req, res) => {
    const user = req.user;
    return res.status(200).json(new ApiResponse(200, user, "Current user fetched successfully"))
})

export const updateUser = asyncHandler(async (req, res) => {
    const { fullName, username, email } = req.body

    if ([fullName, username, email].some((field) => field !== undefined && !field.trim())) {
        throw new ApiError(400, "Fields cannot be empty strings");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName: fullName || req.user?.fullName,
                username: username?.toLowerCase() || req.user?.username,
                email: email || req.user?.email,
            }
        },
        { new: true }
    ).select("-password -refreshToken")

    return res.status(200).json(new ApiResponse(200, user, "User updated successfully"))
})


export const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadCloudinary(avatarLocalPath);

    if (!avatar.secure_url) {
        throw new ApiError(400, "Error while uploading avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                avatar: avatar.secure_url
            }
        }, {
        new: true
    }
    ).select("-password -refreshToken")

    return res.status(200).json(new ApiResponse(200, user, "User avatar updated successfully"))





})


export const updateCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400, "coverImageLocalPath file is missing")
    }

    const coverImage = await uploadCloudinary(coverImageLocalPath);

    if (!coverImage.secure_url) {
        throw new ApiError(400, "Error while uploading coverImage")
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                coverImage: coverImage.secure_url
            }
        }, {
        new: true
    }
    ).select("-password -refreshToken")

    return res.status(200).json(new ApiResponse(200, user, "User coverImage updated successfully"))





})


