import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import dotenv from 'dotenv';
dotenv.config({ path: './.env' });

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

//  Function for file upload on cloudinary.

const fileUploadCloudinary = async (localFilePath) => {
  try {
    if(!localFilePath) return null 
    const response = await cloudinary.uploader.upload(localFilePath, {
        resource_type: "auto"
    })
    console.log("File Uploaded Successfully")
    
    fs.unlinkSync(localFilePath)
    return response;

  } catch (error) {
    fs.unlinkSync(localFilePath)
    return null
  }
};

//  Function for file delete from cloudinary.

const deleteFileFromCloudinary = (fileUrl) => {
  return new Promise((resolve, reject) => {
    const regex = /\/([^/]+)\.[^/]+$/;
    const match = fileUrl.match(regex);
    
    if (!match || !match[1]) {
      return reject("Invalid file URL");
    }

    const publicId = match[1];
    
    cloudinary.uploader.destroy(publicId, (error, result) => {
      if (error) {
        return reject(error);
      }
      resolve(result);
    });
  });
};


export {fileUploadCloudinary, deleteFileFromCloudinary}; 