import type { z } from 'zod';
import type { UserValidation } from './user.validation';

export type TCreateUserArgs = z.infer<
  typeof UserValidation.createUserSchema
>['body'];

export type TUpdateUserProfileArgs = z.infer<
  typeof UserValidation.updateUserProfileSchema
>['body'] & { image?: string };
