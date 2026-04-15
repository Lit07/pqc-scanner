import { NextResponse } from "next/server";
import connectToDatabase from "@/lib/mongodb";
import User from "@/models/User";
import Otp from "@/models/Otp";
import jwt from "jsonwebtoken";

export async function POST(req: Request) {
  try {
    const { email, otp } = await req.json();

    if (!email || !otp) {
      return NextResponse.json({ error: "Email and OTP required" }, { status: 400 });
    }

    await connectToDatabase();

    const otpRecord = await Otp.findOne({ email, otp });

    if (!otpRecord) {
      return NextResponse.json({ error: "Invalid or expired OTP" }, { status: 400 });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Set as verified
    user.isVerified = true;
    await user.save();

    // Clean up OTP
    await Otp.deleteMany({ email });

    // Generate JWT Cookie
    const secret = process.env.JWT_SECRET || "default_fallback_secret_32_chars";
    const token = jwt.sign({ id: user._id, email: user.email }, secret, { expiresIn: "7d" });

    const response = NextResponse.json({ message: "Verified and logged in" }, { status: 200 });
    
    // Set cookie
    response.cookies.set("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 24 * 7, // 1 week
      path: "/",
    });

    return response;

  } catch (error) {
    console.error("Verify Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
