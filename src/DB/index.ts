/* eslint-disable no-console */
import chalk from 'chalk';
import config from '../config';
import { USER_ROLES } from '../enums/user';
import { logger } from '../shared/logger';
import { EGender, Prisma, prisma } from '@/util/db';

const superUser = {
  name: 'Super Admin',
  role: USER_ROLES.ADMIN,
  email: config.admin.email,
  password: config.admin.password as string,
  is_verified: true,
  gender: EGender.MALE,
} satisfies Prisma.UserCreateArgs['data'];

const seedAdmin = async () => {
  try {
    const isExistSuperAdmin = await prisma.user.findFirst({
      where: { role: USER_ROLES.ADMIN },
    });

    if (!isExistSuperAdmin) {
      await prisma.user.create({
        data: superUser,
      });
      logger.info(chalk.green('✔ admin created successfully!'));
    } else {
      console.log('Admin already exists.');
    }
  } catch (error) {
    console.error('Error creating admin:', error);
  }
};

export default seedAdmin;
