import { NextResponse } from "next/server";
import connectToDatabase from "@/lib/mongodb";
import User from "@/models/User";
import Otp from "@/models/Otp";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendOtpEmail } from "@/lib/nodemailer";

export async function POST(req: Request) {
  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return NextResponse.json({ error: "Email and password required" }, { status: 400 });
    }

    await connectToDatabase();

    const user = await User.findOne({ email });

    if (!user) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
    }

    if (!user.isVerified) {
      // Resend OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await Otp.deleteMany({ email });
      await Otp.create({ email, otp });

      try {
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
          await sendOtpEmail(email, otp);
        } else {
          console.warn("EMAIL_USER or EMAIL_PASS not set. Skipping email send. The OTP is:", otp);
        }
      } catch (e) {
        console.error("Failed to send email", e);
      }
      return NextResponse.json({ unverified: true, message: "Please verify your account. New OTP sent." }, { status: 200 });
    }

    // Generate JWT Cookie
    const secret = process.env.JWT_SECRET || "default_fallback_secret_32_chars";
    const token = jwt.sign({ id: user._id, email: user.email }, secret, { expiresIn: "7d" });

    const response = NextResponse.json({ message: "Logged in successfully" }, { status: 200 });
    
    // Set cookie
    response.cookies.set("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 24 * 7, // 1 week
      path: "/",
    });

    return response;

  } catch (error) {
    console.error("Login Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
