import asyncHandler from "../utils/asyncHandler.js";
import APIError from "../utils/APIError.js";
import { User } from "../models/user.models.js";
import uploadOnCloudinary from "../utils/cloudinary.js";
import APIResponse from "../utils/APIResponse.js";

const registerUser = asyncHandler(async (req, res) => {
  const { username, fullName, email, password } = req.body;
  console.log({ username, fullName, email, password });
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new APIError(400, "All fields are required ");
  }

  // check if user is already exists
  const existedUser = User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) throw new APIError(409, "User already exists");

  // handle images
  const avatarLocalPath = req.files?.avatar[0]?.path;
  const coverImageLocalPath = req.files?.coverPath[0]?.path;

  if (!avatarLocalPath) throw new APIError(400, "Avatar file is required");

  const avatarCloudinaryResponse = await uploadOnCloudinary(avatarLocalPath);
  const coverImageCloudinaryResponse =
    await uploadOnCloudinary(coverImageLocalPath);

  if (!avatarCloudinaryResponse)
    throw new APIError(400, "Avatar file is required");

  // Database entry
  const user = await User.create({
    fullName,
    avatar: avatarCloudinaryResponse.url,
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

export { registerUser };
