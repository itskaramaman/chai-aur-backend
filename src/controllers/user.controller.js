import asyncHandler from "../utils/asyncHandler.js";
import APIError from "../utils/APIError.js";
import { User } from "../models/user.models.js";
import uploadOnCloudinary from "../utils/cloudinary.js";
import APIResponse from "../utils/APIResponse.js";
import jwt from "jsonwebtoken";

const options = {
  httpOnly: true,
  secure: true,
};

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (err) {
    throw new APIError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { username, fullName, email, password } = req.body;
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new APIError(400, "All fields are required ");
  }

  // check if user is already exists
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  }).exec();

  if (existedUser) throw new APIError(409, "User already exists");

  // handle images
  const avatarLocalPath = req.files?.avatar[0]?.path;
  const coverImageLocalPath = req.files?.coverImage[0]?.path;

  if (!avatarLocalPath) throw new APIError(400, "Avatar file is required");

  const avatarCloudinaryResponse = await uploadOnCloudinary(avatarLocalPath);
  const coverImageCloudinaryResponse =
    await uploadOnCloudinary(coverImageLocalPath);

  if (!avatarCloudinaryResponse)
    throw new APIError(400, "Avatar file cloudinary URL is required");

  // Database entry
  const user = await User.create({
    fullName,
    avatar: avatarCloudinaryResponse?.url || "",
    coverImage: coverImageCloudinaryResponse?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser)
    throw new APIError(500, "Something went wrong while registering user");

  return res
    .status(201)
    .json(new APIResponse(200, createdUser, "User registered successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if (!username && !email)
    throw new APIError(400, "Username or email is required");

  const user = await User.findOne({ $or: [{ username }, { email }] });
  if (!user) throw new APIError(404, "User does not exist");

  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) throw new APIError(401, "Invalid user credentials");

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new APIResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User logged In Successfully"
      )
    );
});

// secured routes
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    { $set: { refreshToken: undefined } },
    { new: true }
  );

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new APIResponse(200, {}, "User successfully logged out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;
  if (!incomingRefreshToken) throw new APIError(401, "Unauthorized Access");

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) throw new APIError(401, "Invalid Refresh Token");

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new APIError(401, "Refresh Token is expired or user");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
      user._id,
      options
    );

    return res
      .status(200)
      .cookie("accessToken", accessToken)
      .cookie("refreshToken", refreshToken)
      .json(new APIResponse(200, {}, "Access token refreshed"));
  } catch (error) {
    throw new APIError(401, "Invalid Refresh Token");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword)
    throw new APIError(400, "New Password and Confirm Password didn't matched");

  const user = await User.findById(req.user?._id);
  if (!user) throw new APIError(400, "User not real");

  const isPasswordCorrect = await user.isPasswordCorrect(
    oldPassword,
    user.password
  );
  if (!isPasswordCorrect)
    throw new APIError(400, "User's old password invalid");

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new APIResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(
      new APIResponse(200, { user: req.user }, "Fetched User Successfully")
    );
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        fullName: fullName ? fullName : user.fullName,
        email: email ? email : user.email,
      },
    },
    { new: true }
  ).select("-password -refreshToken");

  return res
    .status(200)
    .send(
      new APIResponse(200, { user }, "Account Details Updated Successfully")
    );
});

const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatar = req.file;
  if (!avatar.path) throw new APIError(400, "Avatar is required");

  const cloudinaryUrl = await uploadOnCloudinary(avatar.path);
  if (!cloudinaryUrl) throw new APIError(500, "Error while uploading avatar");

  const user = await User.findByIdAndUpdate(
    req.user._id,
    { $set: { avatar: cloudinaryUrl.url } },
    { new: true }
  ).select("-password -refreshToken");

  return res
    .status(200)
    .send(new APIResponse(200, { user }, "User Avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
  console.log(req.file);
  const coverImage = req.file;
  if (!coverImage.path) throw new APIError(400, "Cover Image is required");

  const cloudinaryUrl = await uploadOnCloudinary(coverImage.path);
  if (!cloudinaryUrl)
    throw new APIError(500, "Error while uploading cover image");

  const user = await User.findByIdAndUpdate(
    req.user._id,
    { $set: { coverImage: cloudinaryUrl.url } },
    { new: true }
  ).select("-password -refreshToken");

  return res
    .status(200)
    .send(
      new APIResponse(200, { user }, "User Cover Image updated successfully")
    );
});

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
};
