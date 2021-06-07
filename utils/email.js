const nodemailer = require('nodemailer');

const sendEmail = async (opitions) => {
    // const transporter = nodemailer.createTransport({
    //     service: 'SendGrid',
    //     auth: {
    //       user: '018d6133218fd5',
    //       pass: 'dfb7e72293d90b',
    //     },
    //   });
      const transporter = nodemailer.createTransport({
        host: 'smtp.mailtrap.io',
        port: 2525,
        auth: {
          user: '018d6133218fd5',
          pass: 'dfb7e72293d90b',
        },
      });
   
      const mailOpitions = {
        from: 'zahid Mahmood <zahidmahmood5455@gmail.com>',
        to: opitions.email,
        subject: opitions.subject,
        text: opitions.message,
      };
    
      //3) Send Emai
      await transporter.sendMail(mailOpitions);
    };
    
    module.exports = sendEmail;
    