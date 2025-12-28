import chalk from 'chalk';
import config from '../config';
import { USER_ROLES } from '../enums/user';
import { logger } from '../shared/logger';
import { prisma } from '../lib/prisma';
import bcrypt from 'bcrypt';

const superUser = {
  name: 'starter backend',
  role: USER_ROLES.ADMIN,
  email: config.admin.email || 'admin@example.com',
  password: config.admin.password || 'defaultPassword',
  phone: '14524578',
  verified: true,
  gender: 'MALE',
};

const seedAdmin = async () => {
  try {
    const isExistSuperAdmin = await prisma.user.findFirst({
      where: { role: USER_ROLES.ADMIN },
    });

    if (!isExistSuperAdmin) {
      const hashedPassword = await bcrypt.hash(
        superUser.password,
        Number(config.bcrypt_salt_rounds),
      );
      await prisma.user.create({
        data: {
          name: superUser.name,
          role: superUser.role,
          email: superUser.email,
          password: hashedPassword,
          phone: superUser.phone,
          verified: superUser.verified,
          gender: superUser.gender,
        },
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
