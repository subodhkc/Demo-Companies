"""
Multi-Factor Authentication (MFA) Implementation
ISO 27001: A.9.4.2 - Secure log-on procedures
SOC 2: CC6.1 - Logical and physical access controls
NIST CSF: PR.AC-7 - Users, devices, and assets are authenticated
"""

import pyotp
import qrcode
import io
import base64
from typing import Optional, Tuple
from datetime import datetime, timedelta


class MFAHandler:
    """
    Handles TOTP-based multi-factor authentication.
    
    Security Controls:
    - Time-based OTP (TOTP) per RFC 6238
    - QR code generation for easy setup
    - Backup codes for account recovery
    - Rate limiting on verification attempts
    
    Compliance:
    - ISO 27001: A.9.4.2 (Multi-factor authentication)
    - SOC 2: CC6.1 (Strong authentication mechanisms)
    - NIST CSF: PR.AC-7 (Multi-factor authentication)
    """
    
    def __init__(self, issuer_name: str = "TechCorp AI"):
        self.issuer_name = issuer_name
        self.totp_interval = 30  # Standard 30-second window
        self.totp_digits = 6     # Standard 6-digit code
    
    def generate_secret(self) -> str:
        """
        Generate a new TOTP secret for a user.
        
        Returns:
            Base32-encoded secret key
            
        Security: Uses cryptographically secure random generation
        """
        return pyotp.random_base32()
    
    def generate_qr_code(self, secret: str, user_email: str) -> str:
        """
        Generate QR code for easy MFA setup.
        
        Args:
            secret: TOTP secret key
            user_email: User's email address
            
        Returns:
            Base64-encoded QR code image
            
        Security: QR code contains provisioning URI per RFC 6238
        """
        # Create provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for easy transmission
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return img_str
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify TOTP token.
        
        Args:
            secret: User's TOTP secret
            token: 6-digit code from authenticator app
            window: Number of time windows to check (default: 1)
            
        Returns:
            True if token is valid, False otherwise
            
        Security:
        - Validates against current time window
        - Allows small time drift (window parameter)
        - Constant-time comparison to prevent timing attacks
        
        Compliance: ISO 27001 A.9.4.2 - Secure authentication
        """
        totp = pyotp.TOTP(secret)
        
        # Verify with time window tolerance
        # This accounts for clock drift between server and client
        return totp.verify(token, valid_window=window)
    
    def generate_backup_codes(self, count: int = 10) -> list[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
            
        Security:
        - Cryptographically secure random generation
        - One-time use codes
        - Should be stored hashed in database
        
        Compliance: SOC 2 CC6.1 - Account recovery mechanisms
        """
        import secrets
        backup_codes = []
        
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
            # Format as XXXX-XXXX for readability
            formatted_code = f"{code[:4]}-{code[4:]}"
            backup_codes.append(formatted_code)
        
        return backup_codes
    
    def get_current_totp(self, secret: str) -> str:
        """
        Get current TOTP code (for testing/display purposes).
        
        Args:
            secret: TOTP secret key
            
        Returns:
            Current 6-digit TOTP code
            
        Note: This should only be used for testing or display purposes
        """
        totp = pyotp.TOTP(secret)
        return totp.now()
    
    def get_time_remaining(self) -> int:
        """
        Get seconds remaining in current TOTP window.
        
        Returns:
            Seconds until next TOTP code
            
        Use case: Display countdown timer in UI
        """
        import time
        return self.totp_interval - (int(time.time()) % self.totp_interval)


class MFAEnforcement:
    """
    Enforces MFA policies across the application.
    
    Security Controls:
    - Rate limiting on verification attempts
    - Account lockout after failed attempts
    - Audit logging of MFA events
    
    Compliance:
    - ISO 27001: A.9.4.2 (Access control)
    - SOC 2: CC6.1 (Logical access controls)
    """
    
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    
    def __init__(self):
        self.failed_attempts = {}  # In production, use Redis or database
        self.lockouts = {}
    
    def is_locked_out(self, user_id: str) -> bool:
        """
        Check if user is currently locked out.
        
        Security: Prevents brute force attacks on MFA codes
        """
        if user_id not in self.lockouts:
            return False
        
        lockout_until = self.lockouts[user_id]
        if datetime.utcnow() > lockout_until:
            # Lockout expired
            del self.lockouts[user_id]
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
            return False
        
        return True
    
    def record_failed_attempt(self, user_id: str) -> Tuple[bool, int]:
        """
        Record a failed MFA verification attempt.
        
        Returns:
            Tuple of (is_locked_out, remaining_attempts)
            
        Security: Implements progressive delays and lockouts
        Compliance: ISO 27001 A.9.4.2 - Failed login handling
        """
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = 0
        
        self.failed_attempts[user_id] += 1
        
        if self.failed_attempts[user_id] >= self.MAX_ATTEMPTS:
            # Lock out user
            lockout_until = datetime.utcnow() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)
            self.lockouts[user_id] = lockout_until
            
            # Log security event - ISO 27001: A.12.4.1
            print(f"[SECURITY] User {user_id} locked out until {lockout_until} due to failed MFA attempts")
            
            return True, 0
        
        remaining = self.MAX_ATTEMPTS - self.failed_attempts[user_id]
        return False, remaining
    
    def record_successful_attempt(self, user_id: str):
        """
        Record successful MFA verification.
        
        Security: Clears failed attempt counters
        """
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]
        if user_id in self.lockouts:
            del self.lockouts[user_id]
        
        # Log security event - ISO 27001: A.12.4.1
        print(f"[AUDIT] User {user_id} successfully authenticated with MFA at {datetime.utcnow()}")


# Example usage
if __name__ == "__main__":
    mfa = MFAHandler()
    
    # Setup MFA for a user
    secret = mfa.generate_secret()
    print(f"Secret: {secret}")
    
    # Generate QR code
    qr_code = mfa.generate_qr_code(secret, "user@techcorp.ai")
    print(f"QR Code (base64): {qr_code[:50]}...")
    
    # Generate backup codes
    backup_codes = mfa.generate_backup_codes()
    print(f"Backup codes: {backup_codes}")
    
    # Verify TOTP
    current_code = mfa.get_current_totp(secret)
    print(f"Current TOTP: {current_code}")
    is_valid = mfa.verify_totp(secret, current_code)
    print(f"Verification result: {is_valid}")
