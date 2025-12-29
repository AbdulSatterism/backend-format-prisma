/* eslint-disable no-console */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */
/* eslint-disable no-unused-expressions */
import { ErrorRequestHandler } from 'express';
import config from '../../config';
import { ZodError } from 'zod';
import { TErrorSource } from '../interface';
import handleZodError from '../errors/handleZodError';
import handlePrismaValidationError from '../errors/handleValidationError';
import handlePrismaKnownError from '../errors/handleCastError';
import AppError from '../errors/AppError';
import { errorLogger } from '../../shared/logger';
import chalk from 'chalk';
import { Prisma } from '@/util/db';

const globalErrorHandler: ErrorRequestHandler = (
  err,
  req,
  res,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  next,
) => {
  config.node_env === 'development'
    ? errorLogger.error(chalk.red('🚨 globalErrorHandler ~~ ', err))
    : errorLogger.error(chalk.red('🚨 globalErrorHandler ~~ ', err));

  let statusCode = 500;
  let message = 'something went wrong';

  let errorSources: TErrorSource = [
    {
      path: '',
      message: 'something went wrong!!',
    },
  ];

  if (err instanceof ZodError) {
    const simplifiedError = handleZodError(err);
    statusCode = simplifiedError?.statusCode;
    message = simplifiedError?.message;
    errorSources = simplifiedError?.errorSources;
  } else if (err instanceof Prisma.PrismaClientValidationError) {
    const simplifiedError = handlePrismaValidationError(err);
    statusCode = simplifiedError?.statusCode;
    message = simplifiedError?.message;
    errorSources = simplifiedError?.errorSources;
  } else if (err instanceof Prisma.PrismaClientKnownRequestError) {
    const simplifiedError = handlePrismaKnownError(err);
    statusCode = simplifiedError?.statusCode;
    message = simplifiedError?.message;
    errorSources = simplifiedError?.errorSources;
  } else if (err instanceof AppError) {
    statusCode = err?.statusCode;
    message = err?.message;
    errorSources = [
      {
        path: '',
        message: err?.message,
      },
    ];
  } else if (err instanceof Error) {
    message = err?.message;
    errorSources = [
      {
        path: '',
        message: err?.message,
      },
    ];
  }

  return res.status(statusCode).json({
    success: false,
    message,
    errorSources,
    stack: config.node_env === 'development' ? err?.stack : null,
  });
};

export default globalErrorHandler;
