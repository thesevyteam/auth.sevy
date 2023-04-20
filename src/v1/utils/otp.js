const formData = require("form-data");
const Mailgun = require("mailgun.js");
const twilio = require("twilio");

const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID;
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

const mg = new Mailgun(formData);
const mailgun = mg.client({
  username: "api",
  key: process.env.MAILGUN_API_KEY,
});
const twilioClient = twilio(twilioAccountSid, twilioAuthToken);

exports.generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000);
};

exports.sendOTPViaEmail = async (email, otp) => {
  const data = {
    from: `Sevy <no-reply@${process.env.MAILGUN_DOMAIN}>`,
    to: [email],
    subject: "Sevy OTP Verification",
    text: `Your Sevy OTP is ${otp}. This OTP is valid for 10 minutes.`,
  };

  try {
    const response = await mailgun.messages.create(
      process.env.MAILGUN_DOMAIN,
      data
    );
    console.log("Email sent:", response);
  } catch (error) {
    console.error("Error sending email:", error);
    throw error;
  }
};

exports.sendOTPViaSMS = async (phoneNumber, otp) => {
  await twilioClient.messages.create({
    body: `Your Sevy OTP is: ${otp}. This OTP is valid for 10 minutes.`,
    from: twilioPhoneNumber,
    to: phoneNumber,
  });
};
