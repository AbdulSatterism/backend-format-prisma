/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-undef */
import type { Express } from 'express';
import { StatusCodes } from 'http-status-codes';
import multer, { FileFilterCallback } from 'multer';
import path from 'path';
import fs from 'fs/promises';
import fsSync from 'fs';
import catchAsync from '../../shared/catchAsync';
import { errorLogger, logger } from '../../shared/logger';
import AppError from '../errors/AppError';
import chalk from 'chalk';

//  File validators with folders
export const fileValidators = {
  images: { validator: /^image\//, folder: 'images' },
  videos: { validator: /^video\//, folder: 'videos' },
  audios: { validator: /^audio\//, folder: 'audios' },
  documents: { validator: /(pdf|word|excel|text)/, folder: 'docs' },
  any: { validator: /.*/, folder: 'others' },
};

export const fileTypes = Object.keys(
  fileValidators,
) as (keyof typeof fileValidators)[];

interface UploadFields {
  [field: string]: {
    default?: string | string[] | null;
    maxCount?: number;
    size?: number; // in bytes
    fileType: (typeof fileTypes)[number];
  };
}

/**
 * Ensure upload folder exists
 */
const ensureDir = async (dir: string) => {
  if (!fsSync.existsSync(dir)) {
    await fs.mkdir(dir, { recursive: true });
  }
};

/**
 * Universal file uploader middleware
 */
const fileUploader = (fields: UploadFields) =>
  catchAsync(async (req, res, next) => {
    try {
      await new Promise<void>((resolve, reject) =>
        upload(fields)(req, res, err => (err ? reject(err) : resolve())),
      );

      const files = req.files as { [field: string]: Express.Multer.File[] };

      Object.keys(fields).forEach(field => {
        if (files?.[field]?.length) {
          const uploadedFiles = files[field].map(
            file => `/${getFolderByMime(file.mimetype)}/${file.filename}`, //  Local path with folder
          );

          req.body[field] =
            (fields[field]?.maxCount || 1) > 1
              ? uploadedFiles
              : uploadedFiles[0];
        } else {
          req.body[field] = fields[field].default;
        }
      });
    } catch (error) {
      errorLogger.error(error);

      Object.keys(fields).forEach(field => {
        req.body[field] = fields[field].default;
      });
    } finally {
      if (req.body?.data) {
        Object.assign(req.body, JSON.parse(req.body.data));
        delete req.body.data;
      }

      next();
    }
  });

export default fileUploader;

/**
 * Universal file retriever (local)
 */
export const fileRetriever = catchAsync(async (req, res) => {
  const filename = req.params.filename.replace(/[^\w.-]/g, '');
  const type = req.params.type || 'others';
  const filePath = path.join(process.cwd(), 'uploads', type, filename);

  try {
    await fs.access(filePath); // ✅ Check file exists
    res.sendFile(filePath);
  } catch {
    throw new AppError(StatusCodes.NOT_FOUND, 'File not found');
  }
});

/**
 * Delete file from local storage
 */
export const deleteFile = async (filename: string) => {
  filename = path.basename(filename);
  const filePath = path.join(process.cwd(), 'uploads', filename);

  try {
    await fs.unlink(filePath);
    logger.info(chalk.green(`✔ file '${filename}' deleted successfully!`));
  } catch (error: any) {
    errorLogger.error(
      chalk.red(`❌ file '${filename}' not deleted!`),
      error?.stack ?? error,
    );
  }
};

//  Helper: get folder by MIME type

const getFolderByMime = (mime: string): string => {
  mime = mime.toLowerCase();
  const matched = Object.values(fileValidators).find(v =>
    v.validator.test(mime),
  );
  return matched?.folder || 'others';
};

// Local storage config
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const folder = getFolderByMime(file.mimetype);
    const dir = path.join(process.cwd(), 'uploads', folder);

    try {
      await ensureDir(dir); // auto-create if missing
      cb(null, dir);
    } catch (err) {
      cb(err as Error, dir);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const name = file.originalname
      .replace(/\..+$/, '')
      .replace(/[^\w]+/g, '-')
      .toLowerCase();
    cb(null, `${name}-${Date.now()}${ext}`);
  },
});

const fileFilter =
  (fields: UploadFields) =>
  (_: any, file: Express.Multer.File, cb: FileFilterCallback) => {
    const fieldType = Object.keys(fields)
      .find(f => file.fieldname === f)
      ?.toLowerCase();
    const fileType = fields[fieldType!]?.fileType;

    const mime = file.mimetype.toLowerCase();

    if (fileValidators[fileType]?.validator.test(mime)) return cb(null, true);

    cb(
      new AppError(
        StatusCodes.BAD_REQUEST,
        `${file.originalname} is not a valid ${fileType} file`,
      ),
    );
  };

const upload = (fields: UploadFields) => {
  const maxSize = Math.max(
    ...Object.values(fields).map(f => f.size || 5 * 1024 * 1024),
  );

  return multer({
    storage,
    fileFilter: fileFilter(fields),
    limits: { fileSize: maxSize }, // ✅ dynamic limit
  }).fields(
    Object.keys(fields).map(field => ({
      name: field,
      maxCount: fields[field].maxCount || undefined,
    })),
  );
};
