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



// Delete file from cloudinary by URL
export const deleteFromCloudinary = async (fileUrl) => {
    if (!fileUrl) return;

    try {
        // Extract public_id from the URL
        // Example: https://res.cloudinary.com/demo/image/upload/v1234567890/folder/image.jpg
        const parts = fileUrl.split("/");
        const fileName = parts[parts.length - 1]; // image.jpg
        const publicIdWithExtension = fileName.split(".")[0]; // image
        const folderPath = parts.slice(parts.indexOf("upload") + 1, -1).join("/"); // folder if any
        const publicId = folderPath
            ? `${folderPath}/${publicIdWithExtension}`
            : publicIdWithExtension;

        // Delete from cloudinary
        const result = await cloudinary.uploader.destroy(publicId);

        if (result.result !== "ok" && result.result !== "not found") {
            console.error("Cloudinary delete error:", result);
        }

        return result;
    } catch (error) {
        console.error("Error deleting from Cloudinary:", error.message);
        return null;
    }
};
