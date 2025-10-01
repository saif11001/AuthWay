const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * sendEmail
 * @param {string} to
 * @param {string} subject
 * @param {string} html
 * @param {boolean} sandbox 
 */
async function sendEmail(to, subject, html, sandbox = false) {
  const msg = {
    to,
    from: process.env.EMAIL_FROM,
    subject,
    html
  };

  if (sandbox) {
    msg.mail_settings = {
      sandbox_mode: {
        enable: true
      }
    };
  }

  return sgMail.send(msg);
}

module.exports = sendEmail;
