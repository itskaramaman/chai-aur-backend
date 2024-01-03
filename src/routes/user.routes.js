import { Router } from "express";
import {
  loginUser,
  registerUser,
  logoutUser,
  refreshAccessToken,
  getCurrentUser,
  changeCurrentPassword,
  updateUserAvatar,
  updateUserCoverImage,
} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import verifyJWT from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
  upload.fields([
    { name: "avatar", maxCount: 1 },
    { name: "coverImage", maxCount: 1 },
  ]),
  registerUser
);

router.route("/login").post(loginUser);

//  secured route
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/change-password").post(verifyJWT, changeCurrentPassword);
router
  .route("/update-avatar")
  .post(upload.single("avatar"), verifyJWT, updateUserAvatar);
router
  .route("/update-cover-image")
  .post(upload.single("coverImage"), verifyJWT, updateUserCoverImage);
router.route("/current-user").get(verifyJWT, getCurrentUser);
export default router;
