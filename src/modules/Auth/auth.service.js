import envConfig from '../../../config/config.service.js';
import UserRepository from '../../DB/Repositories/user.repository.js';
import { encrypt } from '../../Utils/Security/encryption.secuirty.js';
import HttpAppError from '../../Utils/Security/Errors/app.error.js';
import { compareTwoHashes, hash } from '../../Utils/Security/hash.secuirty.js';
import { generateToken } from '../../Utils/Security/token.utils.js';
import { decodedToken } from './../../Utils/Security/token.utils.js';
import { emalilOtpVerification, providersEnum, tokenTypeEnum } from '../../Common/Constants.js';
import { OAuth2Client } from 'google-auth-library';
import { BadRequestException } from '../../Utils/Security/Errors/exceptions.error.js';
import { randomBytes } from 'node:crypto';
import { calculateTTL, set, get, del, incr,ttl,expire } from '../../Common/Services/redis.service.js';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'node:crypto';
import { eventEmitter } from '../../Common/Services/email.service.js';


const userRepo = new UserRepository()


const handleSendingVerificationEmail = async (email, purpose = 'email_verification', subject = 'Email Verification') => {  const otp = crypto.randomInt(10000, 100000).toString()
  const hashedOtp = await hash(otp);
  console.log(otp)
  eventEmitter.emit('sendMailEvent',
    {
      from: '"Example Team" <team@example.com>', // sender address
      to: email,
      subject,
      message: `<h2>Your OTP Code: ${otp}</h2><p>This code is valid for 5 minutes. Do not share it with anyone.</p>`,

    }
  )
set({ key: `${purpose}:${email}`, value: hashedOtp, options: { EX: emalilOtpVerification } })
}


//creating new user

export const SignUp = async (body) => {
  const { firstName, lastName, email, password, gender, age, phoneNumber, role } = body;
  const isUserExist = await userRepo.findUserByEmail(email);
  if (isUserExist) {
    throw new HttpAppError(`user already exists`, 409, { duplicatedEmail: email }, 'EMAIL_CONFLICT');
  }

  // const encryptedPhone = encrypt(phoneNumber)
  const encryptedPhone = phoneNumber
    ? encrypt(phoneNumber)
    : undefined;

  //hashing password

  const hashedPassword = await hash(password)

  //sending email to user
  handleSendingVerificationEmail(email)

  const user = await userRepo.CreateDocument({ firstName, lastName, email, password: hashedPassword, gender, age, phoneNumber: encryptedPhone, role });



  const result = user.toObject();
  delete result.password;
  return result;
};


//build tokens

const buildTokens = (user) => {
  const currentRole = user.role

  const token = generateToken(
    { _id: user._id, role: currentRole },
    envConfig.jwt[currentRole].access_token_secret,
    { expiresIn: envConfig.jwt[currentRole].access_token_expires_in, jwtid: uuidv4() }
  );

  //generate refresh token
  const refreshToken = generateToken(
    { _id: user._id, role: currentRole },
    envConfig.jwt[currentRole].refresh_token_secret,
    { expiresIn: envConfig.jwt[currentRole].refresh_token_expires_in, jwtid: uuidv4() }
  );
  // console.log(token);
  // console.log(envConfig.jwt[user.role].access_token_expires_in)
  const result = user.toObject();
  delete result.password;
  return {

    accessToken: token,
    refreshToken,
  };
}



//signin

export const SignIn = async (data) => {
  const { email, password } = data
  const user = await userRepo.FindOneDocument({ email, provider: providersEnum.SYSTEM });
  if (!user) {
    throw new HttpAppError(
      "wrong email or password",
      400,
      {},
      "INVALID_CREDENTIALS"
    );
  }
  const banKey = `login_ban:${email}`; // Redis key that says "this email is banned right now"
  const failKey = `login_fail:${email}`;  // Redis key that counts the wrong passwords for this email


  //checking if account is banned
    const banTtl = await ttl(banKey);
  if (banTtl > 0) {
    throw new HttpAppError(
      `too many failed attempts, try again in ${Math.ceil(banTtl / 60)} minute(s)`,
      429,
      { retryAfterSeconds: banTtl },
      'ACCOUNT_TEMP_BANNED'
    );
  }

  const isPasswordCorrect = await compareTwoHashes(user.password, password)
  if (!isPasswordCorrect) {
    const fails = await incr(failKey);
    await expire(failKey, 300);
    if (fails >= 5) {
      await set({ key: banKey, value: 'true', options: { EX: 300 } });
      await del(failKey);
    }
    // throw new Error(`wrong email or password`);
    throw new HttpAppError(
      "wrong email or password",
      400,
      {},
      "INVALID_CREDENTIALS"
    );
  }
  await del(failKey);


  //2 step verification login
  if (user.twoStepEnabled) {
  await handleSendingVerificationEmail(email, 'two_step_login', 'Your login code');
  return { twoStepRequired: true };
}
  return buildTokens(user)
}


//refresh token
export const refreshToken = async (userRefeshToken) => {

  const user = await decodedToken({ token: userRefeshToken, tokenType: tokenTypeEnum.REFRESH_TOKEN })
  const currentRole = user.role

  const accessToken = generateToken({ _id: user._id, role: currentRole },
    envConfig.jwt[currentRole].access_token_secret,
    { expiresIn: envConfig.jwt[currentRole].access_token_expires_in })
  return {
    message: 'Token refreshed successfully',
    accessToken,
  };
}

//verify idToken

const verifyIdToken = async (token) => {
  const client = new OAuth2Client();

  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: envConfig.GCP.client_id,
  });
  const payload = ticket.getPayload();
  return payload;
}



//update or create google-signup
const updateOrCreate = async (user, googleTokenPayload) => {
  const { sub, email, given_name, family_name } = googleTokenPayload
  if (user) {
    return userRepo.UpdateDocumentById(user._id, { email: email, firstName: given_name, lastName: family_name }, { new: true })
  }
  else {
    const hashedPassword = await hash(randomBytes(12).toString('hex'))
    return userRepo.CreateDocument({
      googleSub: sub,
      provider: providersEnum.GOOGLE,
      firstName: given_name,
      lastName: family_name || '',
      email,
      password: hashedPassword
    })
  }
}

//google-register


export const googleRegister = async (idToken) => {

  const googleTokenPayload = await verifyIdToken(idToken)
  if (!googleTokenPayload || !googleTokenPayload.email_verified) {
    throw new BadRequestException('not verified email', null, 'NOT-VERIFIED-EMAIL')
  }
  const user = await userRepo.FindOneDocument({ googleSub: googleTokenPayload.sub, provider: providersEnum.GOOGLE })
  const handleUser = await updateOrCreate(user, googleTokenPayload)
  // console.log(buildTokens(handleUser))
  return buildTokens(handleUser)

}

//google-login

export const googleLogin = async (idToken) => {

  const googleTokenPayload = await verifyIdToken(idToken);
  if (!googleTokenPayload || !googleTokenPayload.email_verified) {
    throw new BadRequestException("Google email is not verified", null, 'GOOGLE_EMAIL_NOT_VERIFIED');
  }

  const user = await userRepo.FindOneDocument({ googleSub: googleTokenPayload.sub, provider: providersEnum.GOOGLE });

  if (!user) {
    throw new BadRequestException("User not found. Please register first.", null, 'USER_NOT_FOUND');
  }

  return buildTokens(user)

}

//logout

export const logout = async (accessTokenData, refreshTokenData) => {

  const { exp: accessExpiration, jti: accessId } = accessTokenData
  const { exp: refreshExpiration, jti: refreshId } = refreshTokenData

  const accessTTL = calculateTTL(accessExpiration)
  const refreshTTL = calculateTTL(refreshExpiration)

  set({ key: `bl_${tokenTypeEnum.ACCESS_TOKEN}_${accessId}`, value: "true", options: { EX: accessTTL } })
  set({ key: `bl_${tokenTypeEnum.REFRESH_TOKEN}_refresh_${refreshId}`, value: "true", options: { EX: refreshTTL } })

  return { accessTTL, refreshTTL }
}

//verify otp
const verifyOtp = async (purpose, email, otp) => {
  const hashedOtp = await get(`${purpose}:${email}`)
  if (!hashedOtp) throw new BadRequestException('invalid email or otp is expired', null, 'OTP-INVALID')

  const isValidOtp = await compareTwoHashes(hashedOtp, String(otp))
  if (!isValidOtp) throw new BadRequestException('invalid otp', null, 'invalid-OTP')

  await del(`${purpose}:${email}`)    // one-time use
}


//confirm email

export const confirmEmail = async (mail, otp) => {
  await verifyOtp('email_verification', mail, otp)
  await userRepo.UpdateOneDocument({ email: mail }, { isEmailVerified: true })
  return true;
}

//Request the code when the user is already logged in
export const requestEnableTwoStep = async (userId) => {

  // userId comes from the access token, not from the request body
  const user = await userRepo.FindOneDocument({ _id: userId });
  if (!user) throw new BadRequestException('user not found', null, 'USER_NOT_FOUND');

  // nothing to do if it's already on
  if (user.twoStepEnabled) {
    throw new BadRequestException('2-step verification is already enabled', null, 'TWO_STEP_ALREADY_ENABLED');
  }

  if (!user.isEmailVerified) {
    throw new BadRequestException('verify your email first', null, 'EMAIL_NOT_VERIFIED');
  }

  await handleSendingVerificationEmail(user.email, 'two_step_enable', 'Enable 2-step verification');
  return true;
};

//confirm the code and turn it on

export const confirmEnableTwoStep = async (userId, otp) => {
  const user = await userRepo.FindOneDocument({ _id: userId });
  if (!user) throw new BadRequestException('user not found', null, 'USER_NOT_FOUND');

  await verifyOtp('two_step_enable', user.email, otp);

  await userRepo.UpdateDocumentById(userId, { twoStepEnabled: true });
  return true;
};


//  check the code from the email, then give the tokens(login)
export const confirmLogin = async (email, otp) => {

  await verifyOtp('two_step_login', email, otp);

  const user = await userRepo.FindOneDocument({ email, provider: providersEnum.SYSTEM });
  if (!user) throw new BadRequestException('user not found', null, 'USER_NOT_FOUND');

  return buildTokens(user);
};


//resending email
// send a new verification code when the first one expired or got lost
export const resendVerificationEmail = async (email) => {

  const cooldownKey = `resend_cooldown:email_verification:${email}`;

  const wait = await ttl(cooldownKey);
  if (wait > 0) {
    throw new HttpAppError(
      `wait ${wait} seconds before requesting another code`,
      429,
      { retryAfterSeconds: wait },
      'RESEND_COOLDOWN'
    );
  }

  //checking user existance
  const user = await userRepo.FindOneDocument({ email, provider: providersEnum.SYSTEM });
  if (!user) throw new BadRequestException('user not found', null, 'USER_NOT_FOUND');


  // if the email is already verified
  if (user.isEmailVerified) {
    throw new BadRequestException('email is already verified', null, 'EMAIL_ALREADY_VERIFIED');
  }

//sending code
  await handleSendingVerificationEmail(email);

  //  60 second wait after the code was sent
  await set({ key: cooldownKey, value: 'true', options: { EX: 60 } });
  return true;
};


//  password reset=> email a code to the user
export const forgotPassword = async (email) => {

  const cooldownKey = `resend_cooldown:reset_password:${email}`;

  const wait = await ttl(cooldownKey);
  if (wait > 0) {
    throw new HttpAppError(
      `wait ${wait} seconds before requesting another code`,
      429,
      { retryAfterSeconds: wait },
      'RESEND_COOLDOWN'
    );
  }

  await set({ key: cooldownKey, value: 'true', options: { EX: 60 } });

  const user = await userRepo.FindOneDocument({ email, provider: providersEnum.SYSTEM });

  if (user) {
    await handleSendingVerificationEmail(email, 'reset_password', 'Reset your password');
  }
  return true;
};



// step 2 of password reset: check the code and save the new password
export const resetPassword = async (email, otp, newPassword) => {


  await verifyOtp('reset_password', email, otp);

  // find the user 
  const user = await userRepo.FindOneDocument({ email, provider: providersEnum.SYSTEM });
  if (!user) throw new BadRequestException('user not found', null, 'USER_NOT_FOUND');

  // hashing password
  const hashedPassword = await hash(newPassword);
  await userRepo.UpdateDocumentById(user._id, { password: hashedPassword });


  await del(`login_fail:${email}`);
  await del(`login_ban:${email}`);
  return true;
};