import { Prisma } from '@/util/db';
import { TErrorSource, TGenericErrorResponse } from '../interface';

const handlePrismaValidationError = (
  err: Prisma.PrismaClientValidationError,
): TGenericErrorResponse => {
  const errorSources: TErrorSource = [
    {
      path: '',
      message: err.message,
    },
  ];

  const statusCode = 400;

  return {
    statusCode,
    message: 'Validation error',
    errorSources,
  };
};

export default handlePrismaValidationError;
