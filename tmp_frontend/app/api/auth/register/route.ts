import { NextResponse } from "next/server";
import connectToDatabase from "@/lib/mongodb";
import User from "@/models/User";
import Otp from "@/models/Otp";
import bcrypt from "bcryptjs";
import { sendOtpEmail } from "@/lib/nodemailer";

export async function POST(req: Request) {
  try {
    const { fullName, email, phone, password } = await req.json();

    if (!fullName || !email || !phone || !password) {
      return NextResponse.json({ error: "All fields are required" }, { status: 400 });
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=\[\]{};':"\\|,.<>\/])\S{8,15}$/;
    if (!passwordRegex.test(password)) {
      return NextResponse.json({ error: "Password does not meet complexity requirements." }, { status: 400 });
    }

    await connectToDatabase();

    // Check if user already exists
    let user = await User.findOne({ email });

    if (user) {
      if (user.isVerified) {
        return NextResponse.json({ error: "User already exists" }, { status: 400 });
      }
      // If unverified, update hash and details
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      user.fullName = fullName;
      user.phone = phone;
      await user.save();
    } else {
      // Create new user
      const hashedPassword = await bcrypt.hash(password, 10);
      user = await User.create({
        fullName,
        email,
        phone,
        password: hashedPassword,
        isVerified: false,
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP to DB
    await Otp.deleteMany({ email });
    await Otp.create({ email, otp });

    // Send email safely
    try {
      if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        await sendOtpEmail(email, otp);
      } else {
        console.warn("EMAIL_USER or EMAIL_PASS not set. Skipping email send. The OTP is:", otp);
      }
    } catch (emailErr) {
      console.error("Failed to send OTP email:", emailErr);
      return NextResponse.json({ error: "Failed to send OTP email." }, { status: 500 });
    }

    return NextResponse.json({ message: "OTP sent successfully" }, { status: 200 });

  } catch (error: any) {
    console.error("Register Error:", error);
    return NextResponse.json({ error: "Server Error: " + (error.message || "Unknown error") }, { status: 500 });
  }
}
