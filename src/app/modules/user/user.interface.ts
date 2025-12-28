/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-unused-vars */
import { Model } from 'mongoose';

export type IUser = {
  name: string;
  email: string;
  phone: string;
  password: string;
  googleId?: string;
  facebookId?: string;
  appleId?: string;
  role?: 'ADMIN' | 'USER';
  gender?: 'MALE' | 'FEMALE' | 'OTHERS';
  image?: string;
  age?: number;
  payment?: boolean;
  subscription?: boolean;
  isDeleted?: boolean;
  authentication?: {
    isResetPassword: boolean;
    oneTimeCode: number;
    expireAt: Date;
  };
  verified: boolean;
};

export type UserModal = {
  isExistUserById(id: string): any;
  isExistUserByEmail(email: string): any;
  isAccountCreated(id: string): any;
  isMatchPassword(password: string, hashPassword: string): boolean;
} & Model<IUser>;

/*
  authentication?: {
    isResetPassword: boolean;
    oneTimeCode: number;
    expireAt: Date;
  };
  */
