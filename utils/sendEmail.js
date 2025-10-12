const sgMail = require('@sendgrid/mail');
const config = require('../config/index');

sgMail.setApiKey(config.mail.ApiKey);

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
    from: config.mail.AdminMail,
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
