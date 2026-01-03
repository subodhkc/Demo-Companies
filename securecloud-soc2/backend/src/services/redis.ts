/**
 * Redis Service
 * SOC 2 Control: CC6.1 (Session Management)
 */

import Redis from 'ioredis';
import { config } from '../config';
import { logger } from '../utils/logger';

const redisConfig = {
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  tls: config.redis.tls ? {} : undefined,
  retryDelayOnFailover: 100,
  maxRetriesPerRequest: 3,
};

export const redis = new Redis(redisConfig);

redis.on('connect', () => {
  logger.info('Redis connected');
});

redis.on('error', (err) => {
  logger.error('Redis error', { error: err.message });
});

export default redis;
