import { v2 as cloudinary } from "cloudinary";
import fs from "fs"

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});


export const uploadCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null
        const response = await cloudinary.uploader.upload(localFilePath, { resource_type: "auto" })
        // file uploaded successfully
        console.log("file uploaded successfully", response.secure_url);
        fs.unlinkSync(localFilePath)
        return response;
    }
    catch (error) {
        console.error("Cloudinary upload error :", error)
        if (fs.existsSync(localFilePath)) {
            fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the upload operation got failed

        }
        return null
    }
}