import { generateToken } from "../lib/utils.js";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";

// === SIGNUP CONTROLLER ===
export const signup = async (req, res) => {
  const { fullName, email, password, bio } = req.body;

  try {
    if (!fullName || !email || !password || !bio) {
      return res.status(400).json({ success: false, message: "Missing Details" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "Account already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      fullName,
      email,
      password: hashedPassword,
      bio,
    });

    const token = generateToken(newUser._id);

    const userData = {
      _id: newUser._id,
      fullName: newUser.fullName,
      email: newUser.email,
      bio: newUser.bio,
      profilePic: newUser.profilePic || null,
    };

    res.status(201).json({
      success: true,
      message: "Account Created Successfully",
      token,
      userData,
    });
  } catch (error) {
    console.error("Signup Error:", error.message);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// === LOGIN CONTROLLER ===
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = generateToken(user._id);

    const userData = {
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      bio: user.bio,
      profilePic: user.profilePic || null,
    };

    res.status(200).json({
      success: true,
      message: "Login Successful",
      token,
      userData,
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// === CHECK AUTH CONTROLLER ===
export const checkAuth = (req, res) => {
  const { _id, fullName, email, bio, profilePic } = req.user;
  res.status(200).json({
    success: true,
    user: { _id, fullName, email, bio, profilePic },
  });
};

// === UPDATE PROFILE CONTROLLER ===
export const updateProfile = async (req, res) => {
  try {
    const { profilePic, bio, fullName } = req.body;
    const userId = req.user._id;

    let updatedData = { bio, fullName };

    if (profilePic) {
      const upload = await cloudinary.uploader.upload(profilePic);
      updatedData.profilePic = upload.secure_url;
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updatedData, {
      new: true,
    }).select("-password");

    res.status(200).json({ success: true, user: updatedUser });
  } catch (error) {
    console.error("Update Profile Error:", error.message);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};
