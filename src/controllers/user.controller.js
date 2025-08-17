import { asyncHandler } from "../utills/asyncHandler.js";


export const registerUser = asyncHandler(async (req, res) => {
    res.status(201).json({ message: "ok" })
})

