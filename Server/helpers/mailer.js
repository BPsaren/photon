import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

// Debugging the .env variables
/* console.log('SMTP Configuration:');
console.log('SMTP_MAIL:', process.env.SMTP_MAIL);
console.log('SMTP_PASSWORD:', process.env.SMTP_PASSWORD);
console.log('SMTP_HOST:', process.env.SMTP_HOST);
console.log('SMTP_PORT:', process.env.SMTP_PORT); */
// Create a transport object
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false, // set to true if using SSL
    requireTLS: true,
    auth: {
        user: process.env.SMTP_MAIL,
        pass: process.env.SMTP_PASSWORD
    }
});

// Function to send email
const sendMail = async (email, subject, content) => {
    try {
        const mailOptions = {
            from: process.env.SMTP_MAIL,
            to: email,
            subject: subject,
            html: content
        };

        // Sending the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log("Error sending email:", error);
                return;
            }

            // Check if info is not undefined and contains messageId
            if (info && info.messageId) {
                console.log("Mail sent successfully", info.messageId);
            } else {
                console.log("Mail sent but no messageId available.");
            }
        });
    } catch (error) {
        console.log("Error in sendMail function:", error.message);
    }
};

export default { sendMail };
