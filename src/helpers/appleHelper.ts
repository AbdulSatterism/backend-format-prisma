/* eslint-disable @typescript-eslint/no-explicit-any */
import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { StatusCodes } from 'http-status-codes';
import AppError from '../app/errors/AppError';

/**
 * Create JWKS client for Apple public keys
 */
const client = jwksRsa({
  jwksUri: 'https://appleid.apple.com/auth/keys',
  cache: true,
  rateLimit: true,
});

const getAppleSigningKey = async (kid: string): Promise<string> => {
  try {
    const key = await client.getSigningKey(kid);
    const signingKey = key.getPublicKey();
    if (!signingKey) throw new Error('Unable to retrieve Apple signing key');
    return signingKey;
  } catch (err) {
    throw new AppError(StatusCodes.BAD_REQUEST, 'Failed to load Apple key');
  }
};

/**
 * Verify Apple ID token
 */
export const verifyAppleToken = async (token: string) => {
  try {
    const decodedHeader: any = jwt.decode(token, { complete: true });
    if (!decodedHeader?.header?.kid)
      throw new AppError(StatusCodes.BAD_REQUEST, 'Invalid Apple token header');

    const signingKey = await getAppleSigningKey(decodedHeader.header.kid);

    const verified = jwt.verify(token, signingKey, {
      algorithms: ['RS256'],
      issuer: 'https://appleid.apple.com',
    }) as jwt.JwtPayload;

    return verified;
  } catch {
    throw new AppError(
      StatusCodes.BAD_REQUEST,
      'Invalid or expired Apple identity token',
    );
  }
};
