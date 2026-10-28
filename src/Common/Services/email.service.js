import { EventEmitter } from 'node:events'
import envConfig from '../../../config/config.service.js';
import { BadRequestException } from '../../Utils/Security/Errors/exceptions.error.js';
import { emailTransporter } from '../Clients/email.client.js';


const { email } = envConfig
export const sendEmail = async ({ to, subject = 'No reply', message, attachments = [] }) => {
    if (!message && !attachments?.length)
        { throw new BadRequestException("Message or attachments are requaired", null, 'SEND_MAIL_ERROR');}

    try {
        const info = await emailTransporter.sendMail({
            from: `"NO-reply" <${email.user}>`,
            to,
            subject,
            html: message,
            attachments
        });

        console.log("Message sent: %s", info.messageId);
        return true
    } catch (err) {
        console.error("Error while sending mail:", err);
        throw new BadRequestException("Error while sending mail:", err, 'SEND_MAIL_ERROR');
    }
}


export const eventEmitter = new EventEmitter();
eventEmitter.on('sendMailEvent', ({to,subject = 'No reply',message,attachments =[]}) =>
     {
      sendEmail({
to,
subject,
message,
attachments
  })
    console.log('data received successfully');    
});