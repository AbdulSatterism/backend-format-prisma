import { ZodError } from 'zod';
import { TErrorSource, TGenericErrorResponse } from '../interface';

const handleZodError = (err: ZodError): TGenericErrorResponse => {
  const errorSources: TErrorSource = err.issues.map(issue => {
    return {
      path: issue?.path[issue?.path.length - 1] as string,
      message: issue.message,
    };
  });

  const statusCode = 400;

  return {
    statusCode,
    message: 'validation error',
    errorSources,
  };
};

export default handleZodError;
