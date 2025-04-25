"""
Encryption module for password manager.
Handles encryption and decryption of sensitive data.
"""
import os
import hashlib
import base64
from typing import Tuple, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionManager:
    """Manages encryption and decryption of sensitive data."""
    
    def __init__(self):
        """Initialize the encryption manager."""
        self.iterations = 100000  # Number of iterations for key derivation
        self.key_length = 32  # 256 bits
        self.salt_length = 16  # 128 bits
        self.tag_length = 16  # 128 bits for GCM authentication tag
        
    def generate_salt(self) -> bytes:
        """
        Generate a random salt for key derivation.
        
        Returns:
            bytes: Random salt
        """
        return os.urandom(self.salt_length)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password and salt using PBKDF2.
        
        Args:
            password: Master password
            salt: Random salt
            
        Returns:
            bytes: Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, plaintext: str, key: bytes) -> Tuple[str, str]:
        """
        Encrypt plaintext using AES-GCM.
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key
            
        Returns:
            Tuple[str, str]: Base64-encoded ciphertext and IV
        """
        # Generate a random nonce (IV)
        iv = os.urandom(12)  # 96 bits, recommended for GCM
        
        # Create an AES-GCM cipher with the provided key
        aesgcm = AESGCM(key)
        
        # Encrypt the plaintext
        ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
        
        # Return the base64-encoded ciphertext and IV
        return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')
    
    def decrypt(self, ciphertext_b64: str, iv_b64: str, key: bytes) -> str:
        """
        Decrypt ciphertext using AES-GCM.
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            iv_b64: Base64-encoded IV
            key: Decryption key
            
        Returns:
            str: Decrypted plaintext
            
        Raises:
            Exception: If decryption fails
        """
        try:
            # Decode the base64 ciphertext and IV
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            # Create an AES-GCM cipher with the provided key
            aesgcm = AESGCM(key)
            
            # Decrypt the ciphertext
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            
            # Return the plaintext string
            return plaintext.decode('utf-8')
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def hash_password(self, password: str) -> str:
        """
        Create a secure hash of a password for storage.
        
        Args:
            password: Password to hash
            
        Returns:
            str: Password hash
        """
        # Generate a random salt
        salt = self.generate_salt()
        
        # Hash the password with the salt
        hash_obj = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.iterations
        )
        
        # Combine salt and hash for storage
        combined = salt + hash_obj
        
        # Return base64-encoded hash
        return base64.b64encode(combined).decode('utf-8')
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Password to verify
            stored_hash: Stored hash to compare against
            
        Returns:
            bool: True if the password matches the hash
        """
        try:
            # Decode the stored hash
            decoded = base64.b64decode(stored_hash)
            
            # Extract the salt (first 16 bytes)
            salt = decoded[:self.salt_length]
            
            # Extract the hash (remaining bytes)
            stored_key = decoded[self.salt_length:]
            
            # Hash the provided password with the same salt
            hash_obj = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                self.iterations
            )
            
            # Compare the hashes (constant-time comparison)
            return hash_obj == stored_key
        except Exception:
            return False
