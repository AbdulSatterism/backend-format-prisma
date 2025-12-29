/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-undef */
import chalk from 'chalk';
import { Server } from 'socket.io';
import app from './app';
import config from './config';
import { socketHelper } from './helpers/socketHelper';
import { errorLogger, logger } from './shared/logger';
import seedAdmin from './DB';
import { prisma } from '@/util/db';

//uncaught exception
process.on('uncaughtException', error => {
  errorLogger.error('UnhandleException Detected', error);
  process.exit(1);
});

let server: any;
async function main() {
  try {
    // Test database connection
    await prisma.$connect();
    logger.info(chalk.green('🚀 Database connected successfully'));

    const port =
      typeof config.port === 'number' ? config.port : Number(config.port);

    server = app.listen(port, config.ip_address as string, () => {
      logger.info(
        chalk.yellow(`♻️  Application listening on port:${config.port}`),
      );
    });

    await seedAdmin();

    //socket
    const io = new Server(server, {
      pingTimeout: 60000,
      cors: {
        origin: '*',
      },
    });
    socketHelper.socket(io);
    //@ts-ignore
    global.io = io;
  } catch (error) {
    errorLogger.error(chalk.red('🤢 Failed to connect Database'));
  }

  //handle unhandleRejection
  process.on('unhandledRejection', error => {
    if (server) {
      server.close(async () => {
        errorLogger.error('UnhandleRejection Detected', error);
        await prisma.$disconnect();
        process.exit(1);
      });
    } else {
      process.exit(1);
    }
  });
}

main();

//SIGTERM
process.on('SIGTERM', async () => {
  logger.info('SIGTERM IS RECEIVE');
  if (server) {
    server.close();
  }
  await prisma.$disconnect();
});
