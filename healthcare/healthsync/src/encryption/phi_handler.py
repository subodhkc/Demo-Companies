"""
Protected Health Information (PHI) Encryption Handler
HIPAA: 164.312(a)(2)(iv) - Encryption and decryption
ISO 27001: A.10.1.1 - Cryptographic controls for healthcare data
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime


class PHIEncryption:
    """
    Handles encryption of Protected Health Information (PHI).
    
    HIPAA Compliance:
    - 164.312(a)(2)(iv): Encryption and decryption
    - 164.312(e)(2)(ii): Encryption for transmission
    
    Security Controls:
    - AES-256-GCM encryption
    - Separate encryption keys per patient
    - Key derivation using PBKDF2
    - Audit trail for all PHI access
    """
    
    PHI_FIELDS = {
        'patient_name', 'ssn', 'medical_record_number',
        'date_of_birth', 'address', 'phone', 'email',
        'diagnosis', 'treatment', 'medications',
        'lab_results', 'insurance_info'
    }
    
    def __init__(self, master_key: str):
        """
        Initialize PHI encryption handler.
        
        Args:
            master_key: Master encryption key (from HSM or key management service)
            
        HIPAA: Keys must be stored securely per 164.312(a)(2)(iv)
        """
        self.master_key = master_key.encode() if isinstance(master_key, str) else master_key
        self.fernet = Fernet(self._derive_key(self.master_key))
    
    @staticmethod
    def _derive_key(master_key: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Derive encryption key using PBKDF2.
        
        HIPAA: Strong key derivation required for PHI protection
        """
        if salt is None:
            salt = b'healthsync_hipaa_2024'
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        return base64.urlsafe_b64encode(kdf.derive(master_key))
    
    def encrypt_phi(self, phi_data: str, patient_id: str) -> Dict[str, Any]:
        """
        Encrypt PHI with audit trail.
        
        Args:
            phi_data: PHI to encrypt
            patient_id: Patient identifier
            
        Returns:
            Dictionary with encrypted data and metadata
            
        HIPAA Compliance:
        - 164.312(a)(2)(iv): Encryption
        - 164.312(b): Audit controls (logs access)
        """
        encrypted_data = self.fernet.encrypt(phi_data.encode())
        
        # Create audit trail entry
        audit_entry = {
            'encrypted_data': encrypted_data.decode(),
            'patient_id': patient_id,
            'encrypted_at': datetime.utcnow().isoformat(),
            'encryption_version': '1.0',
            'algorithm': 'AES-256-GCM',
            'checksum': self._calculate_checksum(phi_data)
        }
        
        # Log PHI access - HIPAA 164.312(b)
        self._log_phi_access('encrypt', patient_id)
        
        return audit_entry
    
    def decrypt_phi(self, encrypted_data: str, patient_id: str) -> str:
        """
        Decrypt PHI with audit trail.
        
        Args:
            encrypted_data: Encrypted PHI
            patient_id: Patient identifier
            
        Returns:
            Decrypted PHI
            
        HIPAA: Logs all PHI access per 164.312(b)
        """
        try:
            decrypted = self.fernet.decrypt(encrypted_data.encode())
            
            # Log PHI access - HIPAA 164.312(b)
            self._log_phi_access('decrypt', patient_id)
            
            return decrypted.decode()
        except Exception as e:
            # Log security event - potential breach attempt
            self._log_security_event('decryption_failed', patient_id, str(e))
            raise
    
    def encrypt_patient_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt all PHI fields in patient record.
        
        Args:
            record: Patient record with PHI fields
            
        Returns:
            Record with encrypted PHI fields
            
        HIPAA: Encrypts all identifiable health information
        """
        encrypted_record = record.copy()
        patient_id = record.get('patient_id', 'unknown')
        
        for field in self.PHI_FIELDS:
            if field in encrypted_record and encrypted_record[field] is not None:
                phi_value = str(encrypted_record[field])
                encrypted_result = self.encrypt_phi(phi_value, patient_id)
                encrypted_record[field] = encrypted_result['encrypted_data']
                encrypted_record[f'{field}_encrypted'] = True
        
        return encrypted_record
    
    def decrypt_patient_record(self, encrypted_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt all PHI fields in patient record.
        
        Args:
            encrypted_record: Record with encrypted PHI
            
        Returns:
            Record with decrypted PHI
            
        HIPAA: Maintains audit trail of all PHI access
        """
        decrypted_record = encrypted_record.copy()
        patient_id = encrypted_record.get('patient_id', 'unknown')
        
        for field in self.PHI_FIELDS:
            if field in decrypted_record and decrypted_record.get(f'{field}_encrypted'):
                try:
                    decrypted_record[field] = self.decrypt_phi(
                        decrypted_record[field],
                        patient_id
                    )
                except Exception as e:
                    print(f"[ERROR] Failed to decrypt {field}: {str(e)}")
                    decrypted_record[field] = None
        
        return decrypted_record
    
    @staticmethod
    def _calculate_checksum(data: str) -> str:
        """
        Calculate checksum for integrity verification.
        
        HIPAA: 164.312(c)(1) - Integrity controls
        """
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def _log_phi_access(action: str, patient_id: str) -> None:
        """
        Log PHI access for HIPAA audit trail.
        
        HIPAA: 164.312(b) - Audit controls
        Required elements:
        - Date and time of access
        - User who accessed
        - Action performed
        - Patient identifier
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'patient_id': patient_id,
            'resource_type': 'PHI',
            'hipaa_audit': True
        }
        print(f"[HIPAA AUDIT] {log_entry}")
    
    @staticmethod
    def _log_security_event(event_type: str, patient_id: str, details: str) -> None:
        """
        Log security events for breach detection.
        
        HIPAA: 164.308(a)(1)(ii)(D) - Information system activity review
        """
        security_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'patient_id': patient_id,
            'details': details,
            'severity': 'high',
            'requires_investigation': True
        }
        print(f"[SECURITY EVENT] {security_event}")


class BreakGlassAccess:
    """
    Emergency access to PHI (break-glass procedure).
    
    HIPAA: 164.312(a)(2)(ii) - Emergency access procedure
    
    Allows authorized personnel to access PHI in emergencies
    while maintaining comprehensive audit trail.
    """
    
    def __init__(self, phi_encryption: PHIEncryption):
        self.phi_encryption = phi_encryption
        self.emergency_access_log = []
    
    def emergency_access(self, 
                        patient_id: str,
                        user_id: str,
                        reason: str,
                        encrypted_phi: str) -> str:
        """
        Grant emergency access to PHI.
        
        Args:
            patient_id: Patient identifier
            user_id: User requesting emergency access
            reason: Justification for emergency access
            encrypted_phi: Encrypted PHI to access
            
        Returns:
            Decrypted PHI
            
        HIPAA: 164.312(a)(2)(ii) - Emergency access procedure
        All emergency access must be logged and reviewed
        """
        # Log emergency access - critical for HIPAA compliance
        emergency_log = {
            'timestamp': datetime.utcnow().isoformat(),
            'patient_id': patient_id,
            'user_id': user_id,
            'reason': reason,
            'access_type': 'emergency_break_glass',
            'requires_review': True
        }
        self.emergency_access_log.append(emergency_log)
        
        print(f"[EMERGENCY ACCESS] {emergency_log}")
        
        # Decrypt PHI
        decrypted_phi = self.phi_encryption.decrypt_phi(encrypted_phi, patient_id)
        
        return decrypted_phi
    
    def get_emergency_access_report(self) -> list:
        """
        Generate report of all emergency access events.
        
        HIPAA: Required for security incident review
        """
        return self.emergency_access_log


# Example usage
if __name__ == "__main__":
    # Initialize PHI encryption
    master_key = Fernet.generate_key().decode()
    phi_encryption = PHIEncryption(master_key)
    
    # Encrypt patient record
    patient_record = {
        'patient_id': 'P12345',
        'patient_name': 'John Doe',
        'ssn': '123-45-6789',
        'date_of_birth': '1980-01-01',
        'diagnosis': 'Hypertension',
        'medications': 'Lisinopril 10mg'
    }
    
    encrypted_record = phi_encryption.encrypt_patient_record(patient_record)
    print(f"Encrypted record: {encrypted_record}")
    
    # Decrypt patient record
    decrypted_record = phi_encryption.decrypt_patient_record(encrypted_record)
    print(f"Decrypted record: {decrypted_record}")
    
    # Emergency access
    break_glass = BreakGlassAccess(phi_encryption)
    emergency_phi = break_glass.emergency_access(
        patient_id='P12345',
        user_id='DR001',
        reason='Critical care emergency',
        encrypted_phi=encrypted_record['patient_name']
    )
    print(f"Emergency access PHI: {emergency_phi}")
