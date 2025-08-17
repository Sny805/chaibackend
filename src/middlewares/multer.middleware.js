import multer from "multer";
import path from "path";
import fs from "fs";

// Ensure upload directory exists
const uploadPath = path.join(process.cwd(), "public/temp");
if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath, { recursive: true });
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname); // keep original extension
        cb(null, file.fieldname + "-" + uniqueSuffix + ext);
    },
});

export const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
});
