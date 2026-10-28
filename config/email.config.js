
import envConfig from './config.service.js';

const {email} = envConfig;
export const emailConfig = {
  service: "gmail",
  auth: {
    user: email.user,
    pass: email.pass,
  }
};