import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null;

    // upload the file on cloudinary
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });

    // remove the locally saved file after upload
    fs.unlinkSync(localFilePath);
    return response;
  } catch (err) {
    console.log(err);
    fs.unlinkSync(localFilePath); // remove the locally saved file after upload
  }
};

export default uploadOnCloudinary;
