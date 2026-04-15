import nodemailer from "nodemailer";

export const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export async function sendOtpEmail(to: string, otp: string) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: "Your PNB OTP Code for registeration",
    text: `Your OTP is: ${otp}. It will expire in 10 minutes. Please dont share with anyone.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
        <h2>PNB Account Verification</h2>
        <p>Your one-time password (OTP) is:</p>
        <h1 style="background: #f4f4f4; padding: 10px; display: inline-block; letter-spacing: 5px; color: #000;">${otp}</h1>
        <p>This code will expire in 10 minutes. Please do not share it with anyone.</p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
}
