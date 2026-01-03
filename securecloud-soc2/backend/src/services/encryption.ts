/**
 * Encryption Service
 * SOC 2 Control: CC6.7 (Data Protection)
 * 
 * Provides AES-256-GCM encryption for sensitive data at rest.
 * Keys are managed through AWS KMS with automatic rotation.
 */

import crypto from 'crypto';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { config } from '../config';
import { logger } from '../utils/logger';

// Encryption constants
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

// KMS client for key management
const kmsClient = new KMSClient({ region: config.encryption.kmsRegion });

// Data classification levels
export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
}

// Encryption result structure
interface EncryptionResult {
  ciphertext: string;
  iv: string;
  authTag: string;
  keyId: string;
  algorithm: string;
  classification: DataClassification;
  encryptedAt: string;
}

// Decryption input structure
interface DecryptionInput {
  ciphertext: string;
  iv: string;
  authTag: string;
  keyId: string;
}

/**
 * Generate a data encryption key using KMS
 * SOC 2 Control: CC6.7 - Key management
 */
export const generateDataKey = async (): Promise<{ plaintext: Buffer; encrypted: Buffer }> => {
  try {
    const command = new GenerateDataKeyCommand({
      KeyId: config.encryption.keyId,
      KeySpec: 'AES_256',
    });

    const response = await kmsClient.send(command);

    if (!response.Plaintext || !response.CiphertextBlob) {
      throw new Error('Failed to generate data key');
    }

    return {
      plaintext: Buffer.from(response.Plaintext),
      encrypted: Buffer.from(response.CiphertextBlob),
    };
  } catch (error) {
    logger.error('Failed to generate data key', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    throw error;
  }
};

/**
 * Decrypt a data key using KMS
 */
export const decryptDataKey = async (encryptedKey: Buffer): Promise<Buffer> => {
  try {
    const command = new DecryptCommand({
      KeyId: config.encryption.keyId,
      CiphertextBlob: encryptedKey,
    });

    const response = await kmsClient.send(command);

    if (!response.Plaintext) {
      throw new Error('Failed to decrypt data key');
    }

    return Buffer.from(response.Plaintext);
  } catch (error) {
    logger.error('Failed to decrypt data key', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    throw error;
  }
};

/**
 * Encrypt sensitive data using AES-256-GCM
 * SOC 2 Control: CC6.7 - Encryption at rest
 */
export const encrypt = async (
  plaintext: string,
  classification: DataClassification = DataClassification.CONFIDENTIAL
): Promise<EncryptionResult> => {
  try {
    // Generate a unique IV for each encryption
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Generate data key from KMS
    const { plaintext: dataKey, encrypted: encryptedDataKey } = await generateDataKey();

    // Create cipher
    const cipher = crypto.createCipheriv(ALGORITHM, dataKey, iv);

    // Encrypt the data
    let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
    ciphertext += cipher.final('base64');

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    // Clear the plaintext key from memory
    dataKey.fill(0);

    const result: EncryptionResult = {
      ciphertext,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      keyId: encryptedDataKey.toString('base64'),
      algorithm: ALGORITHM,
      classification,
      encryptedAt: new Date().toISOString(),
    };

    logger.debug('Data encrypted successfully', {
      classification,
      algorithm: ALGORITHM,
    });

    return result;
  } catch (error) {
    logger.error('Encryption failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      classification,
    });
    throw new Error('Encryption failed');
  }
};

/**
 * Decrypt data using AES-256-GCM
 * SOC 2 Control: CC6.7 - Data protection
 */
export const decrypt = async (input: DecryptionInput): Promise<string> => {
  try {
    // Decode components
    const iv = Buffer.from(input.iv, 'base64');
    const authTag = Buffer.from(input.authTag, 'base64');
    const encryptedDataKey = Buffer.from(input.keyId, 'base64');

    // Decrypt the data key using KMS
    const dataKey = await decryptDataKey(encryptedDataKey);

    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, dataKey, iv);
    decipher.setAuthTag(authTag);

    // Decrypt the data
    let plaintext = decipher.update(input.ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');

    // Clear the key from memory
    dataKey.fill(0);

    logger.debug('Data decrypted successfully');

    return plaintext;
  } catch (error) {
    logger.error('Decryption failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    throw new Error('Decryption failed');
  }
};

/**
 * Hash sensitive data using SHA-256 with salt
 * SOC 2 Control: CC6.7 - Data protection
 */
export const hash = (data: string, salt?: string): { hash: string; salt: string } => {
  const useSalt = salt || crypto.randomBytes(SALT_LENGTH).toString('hex');
  const hashedData = crypto
    .createHash('sha256')
    .update(data + useSalt)
    .digest('hex');

  return {
    hash: hashedData,
    salt: useSalt,
  };
};

/**
 * Verify hashed data
 */
export const verifyHash = (data: string, hashedData: string, salt: string): boolean => {
  const { hash: computedHash } = hash(data, salt);
  return crypto.timingSafeEqual(
    Buffer.from(computedHash),
    Buffer.from(hashedData)
  );
};

/**
 * Generate a secure random token
 */
export const generateSecureToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Encrypt field-level data for database storage
 * SOC 2 Control: CC6.7 - Field-level encryption
 */
export const encryptField = async (
  value: string,
  fieldName: string,
  classification: DataClassification
): Promise<string> => {
  const result = await encrypt(value, classification);
  
  // Return as a JSON string for database storage
  return JSON.stringify({
    v: 1, // Version for future compatibility
    c: result.ciphertext,
    i: result.iv,
    t: result.authTag,
    k: result.keyId,
    f: fieldName,
    d: classification,
  });
};

/**
 * Decrypt field-level data from database
 */
export const decryptField = async (encryptedValue: string): Promise<string> => {
  const parsed = JSON.parse(encryptedValue);
  
  return decrypt({
    ciphertext: parsed.c,
    iv: parsed.i,
    authTag: parsed.t,
    keyId: parsed.k,
  });
};

/**
 * Mask sensitive data for logging/display
 * SOC 2 Control: CC6.7 - Data masking
 */
export const maskSensitiveData = (data: string, visibleChars: number = 4): string => {
  if (data.length <= visibleChars) {
    return '*'.repeat(data.length);
  }
  
  const masked = '*'.repeat(data.length - visibleChars);
  return masked + data.slice(-visibleChars);
};

/**
 * Mask email address
 */
export const maskEmail = (email: string): string => {
  const [localPart, domain] = email.split('@');
  if (!domain) return maskSensitiveData(email);
  
  const maskedLocal = localPart.length > 2
    ? localPart[0] + '*'.repeat(localPart.length - 2) + localPart.slice(-1)
    : '*'.repeat(localPart.length);
  
  return `${maskedLocal}@${domain}`;
};
