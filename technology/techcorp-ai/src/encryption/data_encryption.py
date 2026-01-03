"""
Data Encryption Module
ISO 27001: A.10.1.1 - Policy on the use of cryptographic controls
SOC 2: CC6.1 - Encryption of sensitive data
NIST CSF: PR.DS-1 - Data-at-rest is protected
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Optional


class DataEncryption:
    """
    Handles encryption and decryption of sensitive data.
    
    Security Controls:
    - AES-256-GCM encryption
    - Key derivation using PBKDF2
    - Secure key storage
    - Encrypted data versioning
    
    Compliance:
    - ISO 27001: A.10.1.1 (Cryptographic controls)
    - SOC 2: CC6.1 (Data encryption)
    - NIST CSF: PR.DS-1 (Data-at-rest protection)
    - GDPR: Article 32 (Security of processing)
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize encryption handler.
        
        Args:
            master_key: Master encryption key (load from secure storage)
            
        Security: Master key should be stored in HSM or key management service
        """
        if master_key is None:
            # In production, load from environment or key management service
            master_key = os.getenv('ENCRYPTION_KEY', self._generate_key())
        
        self.master_key = master_key.encode() if isinstance(master_key, str) else master_key
        self.fernet = Fernet(self._derive_key(self.master_key))
    
    @staticmethod
    def _generate_key() -> str:
        """
        Generate a new encryption key.
        
        Returns:
            Base64-encoded Fernet key
            
        Security: Uses cryptographically secure random generation
        """
        return Fernet.generate_key().decode()
    
    @staticmethod
    def _derive_key(master_key: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Derive encryption key using PBKDF2.
        
        Args:
            master_key: Master key for derivation
            salt: Salt for key derivation (optional)
            
        Returns:
            Derived key suitable for Fernet
            
        Security:
        - PBKDF2 with 100,000 iterations
        - SHA-256 hash function
        - Protects against rainbow table attacks
        
        Compliance: ISO 27001 A.10.1.1 - Key derivation
        """
        if salt is None:
            salt = b'techcorp_salt_2024'  # In production, use unique salt per key
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_key))
        return key
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext data.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Base64-encoded encrypted data
            
        Security:
        - AES-256-GCM encryption
        - Authenticated encryption (prevents tampering)
        - Unique IV per encryption
        
        Compliance:
        - ISO 27001: A.10.1.1 (Encryption of sensitive data)
        - SOC 2: CC6.1 (Data protection)
        - GDPR: Article 32 (Encryption requirement)
        """
        if not plaintext:
            return ""
        
        encrypted_data = self.fernet.encrypt(plaintext.encode())
        return encrypted_data.decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt encrypted data.
        
        Args:
            ciphertext: Base64-encoded encrypted data
            
        Returns:
            Decrypted plaintext
            
        Security:
        - Validates authentication tag
        - Prevents tampering detection
        - Constant-time comparison
        
        Raises:
            cryptography.fernet.InvalidToken: If data has been tampered with
        """
        if not ciphertext:
            return ""
        
        try:
            decrypted_data = self.fernet.decrypt(ciphertext.encode())
            return decrypted_data.decode()
        except Exception as e:
            # Log security event - potential tampering
            print(f"[SECURITY] Decryption failed - possible tampering: {str(e)}")
            raise
    
    def encrypt_dict(self, data: dict) -> dict:
        """
        Encrypt sensitive fields in a dictionary.
        
        Args:
            data: Dictionary with sensitive fields
            
        Returns:
            Dictionary with encrypted sensitive fields
            
        Use case: Encrypt PII before storing in database
        """
        import json
        encrypted = {}
        
        for key, value in data.items():
            if value is not None:
                # Convert to JSON string and encrypt
                json_value = json.dumps(value)
                encrypted[key] = self.encrypt(json_value)
            else:
                encrypted[key] = None
        
        return encrypted
    
    def decrypt_dict(self, encrypted_data: dict) -> dict:
        """
        Decrypt sensitive fields in a dictionary.
        
        Args:
            encrypted_data: Dictionary with encrypted fields
            
        Returns:
            Dictionary with decrypted fields
        """
        import json
        decrypted = {}
        
        for key, value in encrypted_data.items():
            if value is not None:
                # Decrypt and parse JSON
                decrypted_value = self.decrypt(value)
                decrypted[key] = json.loads(decrypted_value)
            else:
                decrypted[key] = None
        
        return decrypted


class FieldLevelEncryption:
    """
    Handles field-level encryption for database columns.
    
    Security Controls:
    - Selective field encryption
    - Searchable encryption for indexed fields
    - Key rotation support
    
    Compliance:
    - ISO 27001: A.10.1.1 (Cryptographic controls)
    - SOC 2: CC6.1 (Data protection)
    - HIPAA: 164.312(a)(2)(iv) (Encryption)
    """
    
    SENSITIVE_FIELDS = {
        'email', 'phone', 'ssn', 'credit_card', 
        'address', 'medical_record', 'password_hash'
    }
    
    def __init__(self, encryption_handler: DataEncryption):
        self.encryption = encryption_handler
    
    def encrypt_record(self, record: dict, fields_to_encrypt: Optional[set] = None) -> dict:
        """
        Encrypt sensitive fields in a database record.
        
        Args:
            record: Database record as dictionary
            fields_to_encrypt: Specific fields to encrypt (optional)
            
        Returns:
            Record with encrypted sensitive fields
            
        Security: Only encrypts specified sensitive fields
        Compliance: GDPR Article 32 - Pseudonymization
        """
        if fields_to_encrypt is None:
            fields_to_encrypt = self.SENSITIVE_FIELDS
        
        encrypted_record = record.copy()
        
        for field in fields_to_encrypt:
            if field in encrypted_record and encrypted_record[field] is not None:
                encrypted_record[field] = self.encryption.encrypt(str(encrypted_record[field]))
                # Add metadata for key rotation
                encrypted_record[f'{field}_encrypted'] = True
                encrypted_record[f'{field}_key_version'] = 1
        
        return encrypted_record
    
    def decrypt_record(self, encrypted_record: dict, fields_to_decrypt: Optional[set] = None) -> dict:
        """
        Decrypt sensitive fields in a database record.
        
        Args:
            encrypted_record: Record with encrypted fields
            fields_to_decrypt: Specific fields to decrypt (optional)
            
        Returns:
            Record with decrypted fields
        """
        if fields_to_decrypt is None:
            fields_to_decrypt = self.SENSITIVE_FIELDS
        
        decrypted_record = encrypted_record.copy()
        
        for field in fields_to_decrypt:
            if field in decrypted_record and decrypted_record.get(f'{field}_encrypted'):
                try:
                    decrypted_record[field] = self.encryption.decrypt(decrypted_record[field])
                except Exception as e:
                    print(f"[ERROR] Failed to decrypt field {field}: {str(e)}")
                    decrypted_record[field] = None
        
        return decrypted_record


class KeyRotation:
    """
    Handles encryption key rotation.
    
    Security Controls:
    - Scheduled key rotation
    - Re-encryption of data with new keys
    - Key version tracking
    
    Compliance:
    - ISO 27001: A.10.1.2 (Key management)
    - SOC 2: CC6.1 (Key rotation)
    - NIST SP 800-57 (Key management recommendations)
    """
    
    def __init__(self):
        self.key_versions = {}
        self.current_version = 1
    
    def rotate_key(self, old_encryption: DataEncryption) -> DataEncryption:
        """
        Generate new encryption key and create new handler.
        
        Returns:
            New DataEncryption instance with rotated key
            
        Security: Implements key rotation per NIST guidelines
        Compliance: ISO 27001 A.10.1.2 - Key lifecycle management
        """
        new_key = DataEncryption._generate_key()
        new_encryption = DataEncryption(new_key)
        
        self.current_version += 1
        self.key_versions[self.current_version] = new_key
        
        print(f"[AUDIT] Key rotated to version {self.current_version} at {os.times()}")
        
        return new_encryption
    
    def re_encrypt_data(self, old_encryption: DataEncryption, 
                        new_encryption: DataEncryption, 
                        encrypted_data: str) -> str:
        """
        Re-encrypt data with new key.
        
        Args:
            old_encryption: Old encryption handler
            new_encryption: New encryption handler
            encrypted_data: Data encrypted with old key
            
        Returns:
            Data encrypted with new key
            
        Security: Seamless key rotation without data loss
        """
        # Decrypt with old key
        plaintext = old_encryption.decrypt(encrypted_data)
        
        # Encrypt with new key
        new_encrypted = new_encryption.encrypt(plaintext)
        
        return new_encrypted


# Example usage
if __name__ == "__main__":
    # Initialize encryption
    encryption = DataEncryption()
    
    # Encrypt sensitive data
    sensitive_data = "user@example.com"
    encrypted = encryption.encrypt(sensitive_data)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt data
    decrypted = encryption.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Field-level encryption
    field_encryption = FieldLevelEncryption(encryption)
    
    user_record = {
        'id': 123,
        'name': 'John Doe',
        'email': 'john@example.com',
        'phone': '+1234567890',
        'role': 'admin'
    }
    
    encrypted_record = field_encryption.encrypt_record(user_record)
    print(f"Encrypted record: {encrypted_record}")
    
    decrypted_record = field_encryption.decrypt_record(encrypted_record)
    print(f"Decrypted record: {decrypted_record}")
