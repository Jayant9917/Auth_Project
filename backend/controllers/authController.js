import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transpoter from "../config/nodemailer.js";

// Register Function
export const register = async (req, res) => {
  const { name, email, password } = req.body;
  // Check if all fields are filled 
  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "Please fill all the fields",
    });
  }
  //Exception handling
  try {
    const existingUser = await userModel.findOne({ email });
    // check if email already exists
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already exists",
      });
    }
    // Hashing the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    //creating a new user
    const user = new userModel({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();

    //Generating a token 
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    //Setting a cookie  
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //Sending welcome Email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to Hello world",
      text: `welcome to my Auth Website. Your account has been 
      created with email id: ${email}`
    }
    await transpoter.sendMail(mailOptions);

    // Returning a success message 
    return res.json({
      success: true,
      message: "registration successful",
      token,
    });
  } catch (err) {
    res.json({
      success: false,
      message: err.message,
    });
  }
};

// Login Function 
export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Please fill all the fields",
    });
  }
  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Email not found",
      });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Password is incorrect",
      });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.json({
      success: true,
      message: "Login successful",
      token,
    });
  } catch (err) {
    return res.json({
      success: false,
      message: err.message,
    });
  }
};

//Logout function
export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    return res.json({
      success: true,
      message: "Logout successful",
    });
  } catch (err) {
    return res.json({
      success: false,
      message: err.message,
    });
  }
};

//Send Verification OTP to the user's Email
export const sendVerifyOtp = async (req, res) => {
  try{
    const {userId} = req.body;

    const user = await userModel.findById(userId);
    if(user.isAccountVerified){
      return res.json({
        success: false,
        message: "Account already verified"
      })
    }


  }catch(err){
    return res.json({
      success: false,
      message: err.message,
    });
  }
}