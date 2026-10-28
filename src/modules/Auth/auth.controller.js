import { Router } from 'express'
import { SignUp, SignIn, refreshToken, googleLogin, googleRegister, logout, confirmEmail, confirmEnableTwoStep, requestEnableTwoStep, confirmLogin, resendVerificationEmail, forgotPassword, resetPassword } from './auth.service.js';
import { generalLogin, generalSignup, loginSchema, signupSchema } from './auth.validation.js';
import HttpAppError from '../../Utils/Security/Errors/app.error.js';
import { validation } from '../../middleware/validation.middleware.js';
import { BadRequestException } from '../../Utils/Security/Errors/exceptions.error.js';
import { authenticate } from './../../middleware/authentication.middleware.js';
import { decodeRefreshToken } from '../../middleware/decodeRefreshToken.middleware.js';

const authController = Router();

//creating new user

authController.post("/signup", validation(generalSignup), async (req, res) => {

    const result = await SignUp(req.validate.body)
    return res.status(201).json({ message: "user registered succefully", data: result })
})


//signin

authController.post("/signin", validation(generalLogin), async (req, res, next) => {


    const result = await SignIn(req.validate.body)
    const message = result.twoStepRequired ? "otp sent to your email" : "user logged succefully"
    return res.status(200).json({ message, data: result })
})

//refresh token
authController.post('/refresh-token', async (req, res, next) => {

    const { refreshtoken } = req.headers
    if (!refreshtoken) {
        throw new BadRequestException("refresh token is required", null, "MISSING_REFRESH_TOKEN")

    }
    const result = await refreshToken(refreshtoken)
    return res.status(200).json({ message: "token refreshed succefully", data: result })

})


//signup with gmail

authController.post("/google-signup", async (req, res) => {

    const { idToken } = req.body
    if (!idToken) {

        throw new BadRequestException('google id token is required', null, 'MISSING-GOOGLE-ID-TOKEN')

    }
    const result = await googleRegister(idToken)
    return res.status(201).json({ message: "user registered succefully", data: result })

})


//login with gmail

authController.post("/google-login", async (req, res) => {
    const { idToken } = req.body

    console.log(idToken)

    if (!idToken) {

        throw new BadRequestException('google id token is required', null, 'MISSING-GOOGLE-ID-TOKEN')


    }
    const result = await googleLogin(idToken)
    return res.status(200).json({ message: "user loggedin succefully", data: result })
})

//logout

authController.post("/logout", authenticate, decodeRefreshToken, async (req, res) => {

    console.log({ refreshToken: req.refreshTokenData, accessTokenData: req.accessTokenData })
    const result = await logout(req.accessTokenData, req.refreshTokenData)
    return res.status(200).json({ message: "user logged-out succefully", data: result })
})


//confirm email

authController.patch("/confirm-email", async (req, res) => {

    const { email, otp } = req.body
    const result = await confirmEmail(email, otp)
    return res.status(200).json({ message: "email confirmed succefully", data: result })


})

//enable 2-step verification: send the otp (user must be logged in)

authController.post("/2sv/enable", authenticate, async (req, res) => {

    const result = await requestEnableTwoStep(req.accessTokenData._id)
    return res.status(200).json({ message: "otp sent to your email", data: result })

})


//enable 2-step verification: confirm the otp

authController.patch("/2sv/enable/confirm", authenticate, async (req, res) => {

    const { otp } = req.body
    if (!otp) {
        throw new BadRequestException('otp is required', null, 'MISSING-OTP')
    }
    const result = await confirmEnableTwoStep(req.accessTokenData._id, otp)
    return res.status(200).json({ message: "2-step verification enabled succefully", data: result })

})


//login confirmation (2-step verification)

authController.post("/login/confirm", async (req, res) => {

    const { email, otp } = req.body
    if (!email || !otp) {
        throw new BadRequestException('email and otp are required', null, 'MISSING-FIELDS')
    }
    const result = await confirmLogin(email, otp)
    return res.status(200).json({ message: "user logged succefully", data: result })

})


//resend verification email

authController.post("/resend-email", async (req, res) => {

    const { email } = req.body
    if (!email) {
        throw new BadRequestException('email is required', null, 'MISSING-EMAIL')
    }
    const result = await resendVerificationEmail(email)
    return res.status(200).json({ message: "verification code sent", data: result })

})

//forgot password: send the reset code

authController.post("/forgot-password", async (req, res) => {

    const { email } = req.body
    if (!email) {
        throw new BadRequestException('email is required', null, 'MISSING-EMAIL')
    }
    await forgotPassword(email)
    return res.status(200).json({ message: "if the email is registered, a reset code was sent" })

})


//reset password: check the code and save the new password

authController.patch("/reset-password", async (req, res) => {

    const { email, otp, newPassword } = req.body
    if (!email || !otp || !newPassword) {
        throw new BadRequestException('email, otp and newPassword are required', null, 'MISSING-FIELDS')
    }
    await resetPassword(email, otp, newPassword)
    return res.status(200).json({ message: "password reset succefully" })

})








export default authController