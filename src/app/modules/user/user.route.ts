/* eslint-disable @typescript-eslint/no-explicit-any */
import express from 'express';
import { USER_ROLES } from '../../../enums/user';
import auth from '../../middlewares/auth';
import fileUploadHandler from '../../middlewares/fileUploadHandler';

import { UserController } from './user.controller';
import { UserValidation } from './user.validation';
import validateRequest from '../../middlewares/validateRequest';
const router = express.Router();

router.post(
  '/create-user',
  validateRequest(UserValidation.createUserSchema),
  UserController.createUser,
);

router.get('/all-user', auth(USER_ROLES.ADMIN), UserController.getAllUser);

router.patch(
  '/update-profile',
  fileUploadHandler({ image: { fileType: 'images', size: 5 * 1024 * 1024 } }),
  auth(USER_ROLES.USER, USER_ROLES.ADMIN),
  validateRequest(UserValidation.updateUserProfileSchema),
  UserController.updateProfile,
);

router.get(
  '/user',
  auth(USER_ROLES.ADMIN, USER_ROLES.USER),
  UserController.getUserProfile,
);

// router.get('/get-all-users', auth(USER_ROLES.ADMIN), UserController.getAllUser);

router.get(
  '/get-single-user/:id',
  auth(USER_ROLES.ADMIN),
  UserController.getSingleUser,
);

// get user by search by phone
router.get(
  '/user-search',
  auth(USER_ROLES.ADMIN, USER_ROLES.USER),
  UserController.searchByPhone,
);

router.get(
  '/profile',
  auth(USER_ROLES.ADMIN, USER_ROLES.USER),
  UserController.getUserProfile,
);

export const UserRoutes = router;
