import { prisma } from '@/util/db';
import { IResetToken } from './resetToken.interface';

export const ResetTokenHelpers = {
  //token check
  isExistToken: async (token: string): Promise<IResetToken | null> => {
    return await prisma.resetToken.findFirst({ where: { token } });
  },

  //token validity check
  isExpireToken: async (token: string): Promise<boolean> => {
    const currentDate = new Date();
    const resetToken = await prisma.resetToken.findFirst({
      where: {
        token,
        expireAt: {
          gt: currentDate,
        },
      },
    });
    return !!resetToken;
  },
};
