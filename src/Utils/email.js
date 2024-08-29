const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: true,
  auth: {
    user: process.env.EMAIL,
    pass: process.env.APP_PASSWORD,
  },
});

const sendResetOtp = (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: "Password Reset OTP",
    html: `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Password Reset OTP</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              color: #333;
              margin: 0;
              padding: 20px;
            }
            .container {
              max-width: 600px;
              margin: auto;
              padding: 20px;
              border: 1px solid #ddd;
              border-radius: 8px;
            }
            .header {
              background-color: #f4f4f4;
              padding: 10px;
              text-align: center;
              border-bottom: 1px solid #ddd;
            }
            .footer {
              margin-top: 20px;
              font-size: 0.8em;
              color: #666;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Password Reset Request</h1>
            </div>
            <p>Hello,</p>
            <p>Your OTP for password reset is <strong>${otp}</strong>. It is valid for 10 minutes.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log("passowrd reset OTP email sent" + info.response);
    }
  });
};

module.exports = { sendResetOtp };
