/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import bcrypt from 'bcryptjs';
import { StatusCodes } from 'http-status-codes';
import { JwtPayload, Secret } from 'jsonwebtoken';
import config from '../../../config';
import { emailHelper } from '../../../helpers/emailHelper';
import { jwtHelper } from '../../../helpers/jwtHelper';
import { emailTemplate } from '../../../shared/emailTemplate';
import {
  IAuthResetPassword,
  IChangePassword,
  ILoginData,
  IVerifyEmail,
} from '../../../types/auth';
// import cryptoToken from '../../../util/cryptoToken';
import generateOTP from '../../../util/generateOTP';

import AppError from '../../errors/AppError';
import unlinkFile from '../../../shared/unlinkFile';
import { downloadImage, facebookToken } from './auth.lib';
import { verifyAppleToken } from '../../../helpers/appleHelper';
import generateSecurePassword from '../../../util/generateSecurePassword';
import { prisma } from '@/util/db';

//login
const loginUserFromDB = async (payload: ILoginData) => {
  const { email, password } = payload;
  const isExistUser = await prisma.user.findFirst({
    where: { email },
  });
  if (!isExistUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, "User doesn't exist!");
  }

  //check verified and status
  if (!isExistUser.is_verified) {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Please verify your account, then try to login again',
    );
  }

  //check match password
  if (!(await bcrypt.compare(password, isExistUser.password))) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Password is incorrect!');
  }

  const tokenPayload = {
    id: isExistUser.id,
    role: isExistUser.role,
    email: isExistUser.email,
  };

  //create access token
  const accessToken = jwtHelper.createToken(
    tokenPayload,
    config.jwt.jwt_secret as Secret,
    config.jwt.jwt_expire_in as string,
  );

  //create refresh token
  const refreshToken = jwtHelper.createToken(
    tokenPayload,
    config.jwt.jwtRefreshSecret as Secret,
    config.jwt.jwtRefreshExpiresIn as string,
  );

  // send user data without password
  const { password: _, ...userWithoutPassword } = isExistUser;

  return { user: userWithoutPassword, accessToken, refreshToken };
};

//forget password
const forgetPasswordToDB = async (email: string) => {
  const isExistUser = await prisma.user.findFirst({
    where: { email },
  });

  if (!isExistUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, "User doesn't exist!");
  }

  //send mail
  const otp = generateOTP();

  const forgetPassword = emailTemplate.resetPassword({
    email,
    otp,
  });
  emailHelper.sendEmail(forgetPassword);

  //save to DB
  await prisma.user.update({
    where: { id: isExistUser.id },
    data: {
      auth_one_time_code: otp,
      auth_expire_at: new Date(Date.now() + 20 * 60000),
    },
  });
};

const verifyEmailToDB = async (payload: IVerifyEmail) => {
  const { email, oneTimeCode } = payload;

  const isExistUser = await prisma.user.findFirst({
    where: { email },
  });

  if (!isExistUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, "User doesn't exist!");
  }

  if (!oneTimeCode) {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Please give the otp, check your email we send a code',
    );
  }

  // console.log(isExistUser.auth_one_time_code, { payload });
  if (isExistUser.auth_one_time_code !== oneTimeCode) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'You provided wrong otp');
  }

  const date = new Date();
  if (isExistUser.auth_expire_at && date > isExistUser.auth_expire_at) {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Otp already expired, Please try again',
    );
  }

  const tokenPayload = {
    id: isExistUser.id,
    role: isExistUser.role,
    email: isExistUser.email,
  };

  //create access token
  const accessToken = jwtHelper.createToken(
    tokenPayload,
    config.jwt.jwt_secret as Secret,
    config.jwt.jwt_expire_in as string,
  );

  //create refresh token
  const refreshToken = jwtHelper.createToken(
    tokenPayload,
    config.jwt.jwtRefreshSecret as Secret,
    config.jwt.jwtRefreshExpiresIn as string,
  );

  let message;
  let data;

  if (!isExistUser.is_verified) {
    await prisma.user.update({
      where: { id: isExistUser.id },
      data: {
        is_verified: true,
        auth_one_time_code: null,
        auth_expire_at: null,
      },
    });
    message = 'Your email has been successfully verified.';
    data = { user: isExistUser, accessToken, refreshToken };
  } else {
    await prisma.user.update({
      where: { id: isExistUser.id },
      data: {
        auth_is_reset_password: true,
        auth_one_time_code: null,
        auth_expire_at: null,
      },
    });

    // const createToken = cryptoToken();
    await prisma.resetToken.create({
      data: {
        user_id: isExistUser.id,
        token: accessToken,
        expire_at: new Date(Date.now() + 20 * 60000),
      },
    });
    message = 'Verification Successful';
    data = { user: isExistUser, accessToken, refreshToken };
  }

  return { data, message };
};

const resetPasswordToDB = async (
  token: string,
  payload: IAuthResetPassword,
) => {
  const { newPassword } = payload;

  //isExist token
  const isExistToken = await prisma.resetToken.findFirst({
    where: { token },
  });

  if (!isExistToken) {
    throw new AppError(StatusCodes.UNAUTHORIZED, 'You are not authorized');
  }

  //user permission check
  const isExistUser = await prisma.user.findUnique({
    where: { id: isExistToken.user_id },
  });
  if (!isExistUser?.auth_is_reset_password) {
    throw new AppError(
      StatusCodes.UNAUTHORIZED,
      "You don't have permission to change the password. Please click again to 'Forgot Password'",
    );
  }

  //validity check
  const tokenData = await prisma.resetToken.findFirst({
    where: { token },
  });

  const date = new Date();
  const isValid =
    tokenData && tokenData.expire_at && date < tokenData.expire_at;

  if (!isValid) {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Token expired, Please click again to the forget password',
    );
  }

  const hashPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  await prisma.user.update({
    where: { id: isExistToken.user_id },
    data: {
      password: hashPassword,
      auth_is_reset_password: false,
    },
  });
};

const changePasswordToDB = async (
  user: JwtPayload,
  payload: IChangePassword,
) => {
  const { currentPassword, newPassword } = payload;

  const isExistUser = await prisma.user.findUnique({
    where: { id: user.id },
  });
  if (!isExistUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, "User doesn't exist!");
  }

  //current password match
  if (
    currentPassword &&
    !(await bcrypt.compare(currentPassword, isExistUser.password))
  ) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Password is incorrect');
  }

  //newPassword and current password
  if (currentPassword === newPassword) {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Please give different password from current password',
    );
  }

  //hash password
  const hashPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashPassword },
  });
};

const deleteAccountToDB = async (user: JwtPayload) => {
  const result = await prisma.user.delete({
    where: { id: user?.id },
  });
  if (!result) {
    throw new AppError(StatusCodes.NOT_FOUND, 'No User found');
  }

  return result;
};

const newAccessTokenToUser = async (token: string) => {
  // Check if the token is provided
  if (!token) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Token is required!');
  }

  const verifyUser = jwtHelper.verifyToken(
    token,
    config.jwt.jwtRefreshSecret as Secret,
  );

  const isExistUser = await prisma.user.findUnique({
    where: { id: verifyUser?.id },
  });
  if (!isExistUser) {
    throw new AppError(StatusCodes.UNAUTHORIZED, 'Unauthorized access');
  }

  //create token
  const accessToken = jwtHelper.createToken(
    { id: isExistUser.id, role: isExistUser.role, email: isExistUser.email },
    config.jwt.jwt_secret as Secret,
    config.jwt.jwt_expire_in as string,
  );

  return { accessToken };
};

const resendVerificationEmailToDB = async (email: string) => {
  // Find the user by ID
  const existingUser = await prisma.user.findFirst({
    where: { email },
  });

  if (!existingUser) {
    throw new AppError(
      StatusCodes.NOT_FOUND,
      'User with this email does not exist!',
    );
  }

  if (existingUser?.is_verified) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'User is already verified!');
  }

  // Generate OTP and prepare email
  const otp = generateOTP();

  const accountEmailTemplate = emailTemplate.createAccount({
    email,
    name: existingUser.name,
    otp,
  });
  emailHelper.sendEmail(accountEmailTemplate);

  // Update user with authentication details
  await prisma.user.update({
    where: { id: existingUser.id },
    data: {
      auth_one_time_code: otp,
      auth_expire_at: new Date(Date.now() + 20 * 60000),
    },
  });
};

//! login with google
/*
interface IGoogleLoginPayload {
  email: string;
  name: string;
  image?: string;
  uid: string;
}

const googleLogin = async (payload: IGoogleLoginPayload) => {
  const { email, name, image, uid } = payload;

  if (!email || !uid) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Email and UID are required');
  }

  // Check if user exists by email
  let user = await prisma.user.findFirst({
    where: { email },
  });

  if (user?.image && image) {
    unlinkFile(user?.image);
  }

  if (!user) {
    // Create new user if doesn't exist
    // Use a cryptographically secure random password for social login users
    const securePassword = await bcrypt.hash(
      generateSecurePassword(),
      Number(config.bcrypt_salt_rounds),
    );
    user = await prisma.user.create({
      data: {
        email,
        name,
        image: image || '/default/user.jpg',
        google_id: uid,
        role: 'USER',
        is_verified: true,
        password: securePassword,
        phone: '',
      },
    });
  } else if (!user.google_id) {
    // Update existing user with Google ID if they haven't logged in with Google before
    user = await prisma.user.update({
      where: { id: user.id },
      data: {
        google_id: uid,
        is_verified: true,
        image: image || user.image,
      },
    });
  }

  if (!user) {
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Failed to create or update user',
    );
  }

  // Generate tokens for authentication
  const tokenPayload = {
    id: user.id,
    email: user.email,
    role: user.role,
  };

  const accessToken = jwtHelper.createToken(
    tokenPayload,
    config.jwt.jwt_secret as Secret,
    config.jwt.jwt_expire_in as string,
  );

  const refreshToken = jwtHelper.createToken(
    tokenPayload,
    config.jwt.jwtRefreshSecret as Secret,
    config.jwt.jwtRefreshExpiresIn as string,
  );

  // Remove sensitive data before sending response
  const { password, ...userObject } = user;

  return {
    user: userObject,
    accessToken,
    refreshToken,
  };
};

const facebookLogin = async (payload: { token: string }) => {
  if (!payload.token) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Facebook token is required');
  }

  try {
    const userData = await facebookToken(payload.token);

    if (!userData?.email) {
      throw new AppError(
        StatusCodes.BAD_REQUEST,
        'Unable to get email from Facebook account',
      );
    }

    // Download Facebook image and get local URL/path
    let localImage = '';
    if (userData.picture?.data?.url) {
      localImage = await downloadImage(
        userData.picture.data.url,
        userData?.id || '',
      );
    }

    const userFields = {
      name: userData.name || '',
      email: userData.email,
      image: localImage || '/default/user.jpg',
      facebookId: userData.id,
      role: 'USER' as const,
      verified: true,
    };

    let user = await prisma.user.findFirst({
      where: {
        OR: [{ email: userData.email }, { facebook_id: userData.id }],
      },
    });

    if (user?.image && localImage) {
      unlinkFile(user?.image);
    }

    if (!user) {
      const securePassword = await bcrypt.hash(
        generateSecurePassword(),
        Number(config.bcrypt_salt_rounds),
      );
      user = await prisma.user.create({
        data: {
          ...userFields,
          password: securePassword,
          phone: '',
        },
      });
    } else if (!user.facebook_id) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          ...userFields,
          image: userFields.image || user.image,
          name: userFields.name || user.name,
        },
      });
    }

    if (!user) {
      throw new AppError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        'Failed to create or update user',
      );
    }

    const tokenPayload = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    const [accessToken, refreshToken] = await Promise.all([
      jwtHelper.createToken(
        tokenPayload,
        config.jwt.jwt_secret as Secret,
        config.jwt.jwt_expire_in as string,
      ),
      jwtHelper.createToken(
        tokenPayload,
        config.jwt.jwtRefreshSecret as Secret,
        config.jwt.jwtRefreshExpiresIn as string,
      ),
    ]);

    const { password, ...userObject } = user;

    return { user: userObject, accessToken, refreshToken };
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Error processing Facebook login',
    );
  }
};

const appleLogin = async (payload: { token: string }) => {
  if (!payload.token)
    throw new AppError(StatusCodes.BAD_REQUEST, 'Apple token is required');

  try {
    // Step 1 — Verify Apple ID token
    const appleData = await verifyAppleToken(payload.token);

    if (!appleData?.email) {
      throw new AppError(
        StatusCodes.BAD_REQUEST,
        'Unable to retrieve email from Apple account',
      );
    }

    // Step 2 — Prepare user fields
    const userFields = {
      name: appleData.name || '',
      email: appleData.email,
      appleId: appleData.sub,
      role: 'USER' as const,
      verified: true,
    };

    // Step 3 — Find or create user
    let user = await prisma.user.findFirst({
      where: {
        OR: [{ email: appleData.email }, { apple_id: appleData.sub }],
      },
    });

    if (!user) {
      const securePassword = await bcrypt.hash(
        generateSecurePassword(),
        Number(config.bcrypt_salt_rounds),
      );
      user = await prisma.user.create({
        data: {
          ...userFields,
          password: securePassword,
          phone: '',
        },
      });
    } else if (!user.apple_id) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          ...userFields,
          name: userFields.name || user.name,
        },
      });
    }

    if (!user) {
      throw new AppError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        'Failed to create or update user',
      );
    }

    // Step 4 — Generate access & refresh tokens
    const tokenPayload = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    const [accessToken, refreshToken] = await Promise.all([
      jwtHelper.createToken(
        tokenPayload,
        config.jwt.jwt_secret as Secret,
        config.jwt.jwt_expire_in as string,
      ),
      jwtHelper.createToken(
        tokenPayload,
        config.jwt.jwtRefreshSecret as Secret,
        config.jwt.jwtRefreshExpiresIn as string,
      ),
    ]);

    // Step 5 — Prepare response
    const { password, ...userObject } = user;
    return { user: userObject, accessToken, refreshToken };
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Error processing Apple login',
    );
  }
};

*/

export const AuthService = {
  verifyEmailToDB,
  loginUserFromDB,
  forgetPasswordToDB,
  resetPasswordToDB,
  changePasswordToDB,
  deleteAccountToDB,
  newAccessTokenToUser,
  resendVerificationEmailToDB,
};
