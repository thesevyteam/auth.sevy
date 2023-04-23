const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const multerUpload = multer({
  storage: new CloudinaryStorage({
    cloudinary: cloudinary,
    params: (req, file) => {
      if (file.fieldname === "id") {
        return {
          folder: "sevy/id_cards",
          allowed_formats: ["jpg", "png", "jpeg", "pdf"],
        };
      } else if (file.fieldname === "profile_picture") {
        return {
          folder: "sevy/profile_pictures",
          allowed_formats: ["jpg", "png", "jpeg"],
        };
      }
    },
  }),
}).fields([
  { name: "id", maxCount: 1 },
  { name: "profile_picture", maxCount: 1 },
]);

module.exports = {
  multerUpload,
};
