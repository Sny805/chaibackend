
import { asyncHandler } from "../utills/asyncHandler.js";
import { ApiError } from "../utills/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadCloudinary } from "../utills/cloudnary.js";
import { ApiResponse } from "../utills/ApiResponse.js";


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

