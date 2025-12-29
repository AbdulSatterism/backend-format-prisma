/* eslint-disable no-undef */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-unused-vars */
import { StatusCodes } from 'http-status-codes';
import { JwtPayload } from 'jsonwebtoken';
import { USER_ROLES } from '../../../enums/user';
import { emailHelper } from '../../../helpers/emailHelper';
import { emailTemplate } from '../../../shared/emailTemplate';
import generateOTP from '../../../util/generateOTP';

import { IUserCreate, IUserUpdate } from './user.interface';
import { UserHelpers } from './user.model';
import unlinkFile from '../../../shared/unlinkFile';
import AppError from '../../errors/AppError';
import bcrypt from 'bcryptjs';
import config from '../../../config';
import { prisma } from '@/util/db';

const createUserFromDb = async (payload: IUserCreate) => {
  // Check if user exists
  const existingUser = await UserHelpers.isExistUserByEmail(payload.email);
  if (existingUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Email already used');
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(
    payload.password,
    Number(config.bcrypt_salt_rounds),
  );

  const result = await prisma.user.create({
    data: {
      ...payload,
      password: hashedPassword,
      role: USER_ROLES.USER,
    },
  });

  if (!result) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Failed to create user');
  }

  const otp = generateOTP();
  const emailValues = {
    name: result.name,
    otp,
    email: result.email,
  };

  const accountEmailTemplate = emailTemplate.createAccount(emailValues);
  emailHelper.sendEmail(accountEmailTemplate);

  // Update user with authentication details
  const updatedUser = await prisma.user.update({
    where: { id: result.id },
    data: {
      authOneTimeCode: otp,
      authExpireAt: new Date(Date.now() + 20 * 60000),
    },
  });

  if (!updatedUser) {
    throw new AppError(StatusCodes.NOT_FOUND, 'User not found for update');
  }

  return result;
};

const getAllUsers = async (query: Record<string, unknown>) => {
  const { page, limit } = query;
  const pages = parseInt(page as string) || 1;
  const size = parseInt(limit as string) || 10;
  const skip = (pages - 1) * size;

  const [result, total] = await Promise.all([
    prisma.user.findMany({
      skip,
      take: size,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.user.count(),
  ]);

  const totalPage = Math.ceil(total / size);

  return {
    data: result,
    meta: {
      page: pages,
      limit: size,
      totalPage,
      total,
    },
  };
};

const getUserProfileFromDB = async (user: JwtPayload) => {
  const { id } = user;
  const isExistUser = await prisma.user.findUnique({
    where: { id },
  });

  if (!isExistUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, "User doesn't exist!");
  }

  return isExistUser;
};

const updateProfileToDB = async (user: JwtPayload, payload: IUserUpdate) => {
  const { id } = user;
  const isExistUser = await UserHelpers.isExistUserById(id);

  if (!isExistUser) {
    throw new AppError(StatusCodes.BAD_REQUEST, "User doesn't exist!");
  }

  if (!isExistUser.verified) {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Please verify your account first',
    );
  }

  if (payload.image && isExistUser.image) {
    unlinkFile(isExistUser.image);
  }

  const updateDoc = await prisma.user.update({
    where: { id },
    data: payload,
  });

  return updateDoc;
};

const getSingleUser = async (id: string) => {
  const result = await prisma.user.findUnique({
    where: { id },
  });
  return result;
};

// search user by phone
const searchUserByPhone = async (searchTerm: string, userId: string) => {
  let result;

  if (searchTerm) {
    result = await prisma.user.findMany({
      where: {
        phone: {
          contains: searchTerm,
          mode: 'insensitive',
        },
        id: {
          not: userId,
        },
      },
    });
  } else {
    result = await prisma.user.findMany({
      where: {
        id: {
          not: userId,
        },
      },
      take: 10,
    });
  }

  return result;
};

export const UserService = {
  createUserFromDb,
  getUserProfileFromDB,
  updateProfileToDB,
  getSingleUser,
  searchUserByPhone,
  getAllUsers,
};
