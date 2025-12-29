import { Prisma } from '@/util/db';
import { TErrorSource, TGenericErrorResponse } from '../interface';

const handlePrismaKnownError = (
  err: Prisma.PrismaClientKnownRequestError,
): TGenericErrorResponse => {
  let errorSources: TErrorSource = [];
  let message = 'Database error';

  // Handle unique constraint violation
  if (err.code === 'P2002') {
    const fields = (err.meta?.target as string[]) || [];
    errorSources = fields.map(field => ({
      path: field,
      message: `${field} already exists`,
    }));
    message = 'Unique constraint violation';
  }
  // Handle foreign key constraint error
  else if (err.code === 'P2003') {
    errorSources = [
      {
        path: '',
        message: 'Foreign key constraint failed',
      },
    ];
  }
  // Handle record not found
  else if (err.code === 'P2025') {
    errorSources = [
      {
        path: '',
        message: 'Record not found',
      },
    ];
    message = 'Record not found';
  } else {
    errorSources = [
      {
        path: '',
        message: err.message,
      },
    ];
  }

  const statusCode = 400;

  return {
    statusCode,
    message,
    errorSources,
  };
};

export default handlePrismaKnownError;
