"""
Password generator module for the password manager.
Handles generation of secure random passwords with configurable settings.
"""
import re
import secrets
import string
from typing import Dict


class PasswordGenerator:
    """Handles password generation and strength evaluation."""
    
    def __init__(self):
        """Initialize the password generator."""
        self.lowercase_letters = string.ascii_lowercase
        self.uppercase_letters = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
    
    def generate_password(self, length: int = 16, use_uppercase: bool = True,
                         use_digits: bool = True, use_symbols: bool = True) -> str:
        """
        Generate a secure random password with the specified characteristics.
        
        Args:
            length: Length of the password (default: 16)
            use_uppercase: Include uppercase letters (default: True)
            use_digits: Include digits (default: True)
            use_symbols: Include special symbols (default: True)
            
        Returns:
            str: Generated password
        
        Raises:
            ValueError: If length is too short or no character sets are selected
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        # Build the character set based on selected options
        charset = self.lowercase_letters  # Always include lowercase
        
        if use_uppercase:
            charset += self.uppercase_letters
        if use_digits:
            charset += self.digits
        if use_symbols:
            charset += self.symbols
        
        # Ensure we have characters to choose from
        if not charset:
            raise ValueError("At least one character set must be selected")
        
        # Generate password
        password = ""
        for _ in range(length):
            password += secrets.choice(charset)
        
        # Ensure the password contains at least one character from each selected set
        # This avoids the unlikely case where, for example, no uppercase letters
        # are included despite them being allowed
        
        # Always include at least one lowercase
        if not any(c in self.lowercase_letters for c in password):
            # Replace a random character with a lowercase letter
            password = self._replace_random_char(password, self.lowercase_letters)
        
        if use_uppercase and not any(c in self.uppercase_letters for c in password):
            password = self._replace_random_char(password, self.uppercase_letters)
            
        if use_digits and not any(c in self.digits for c in password):
            password = self._replace_random_char(password, self.digits)
            
        if use_symbols and not any(c in self.symbols for c in password):
            password = self._replace_random_char(password, self.symbols)
        
        return password
    
    def _replace_random_char(self, password: str, charset: str) -> str:
        """
        Replace a random character in the password with a character from the given set.
        
        Args:
            password: The password to modify
            charset: Character set to sample from
            
        Returns:
            str: Modified password
        """
        pos = secrets.randbelow(len(password))
        char = secrets.choice(charset)
        return password[:pos] + char + password[pos+1:]
    
    def evaluate_strength(self, password: str) -> str:
        """
        Evaluate the strength of a password.
        
        Args:
            password: Password to evaluate
            
        Returns:
            str: Password strength rating ('Weak', 'Medium', 'Strong', or 'Very Strong')
        """
        # Calculate score based on various factors
        score = 0
        
        # Length
        if len(password) >= 12:
            score += 3
        elif len(password) >= 10:
            score += 2
        elif len(password) >= 8:
            score += 1
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 1
        
        # Check for common patterns that weaken passwords
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):  # Same character repeated 3+ times
            score -= 1
        
        # Sequential characters
        if any(seq in password.lower() for seq in [
            'abcdef', 'ghijkl', 'mnopqr', 'stuvwx', 'xyz',
            '123456', '789012', '654321'
        ]):
            score -= 1
        
        # Convert score to rating
        if score <= 2:
            return "Weak"
        elif score <= 4:
            return "Medium"
        elif score <= 6:
            return "Strong"
        else:
            return "Very Strong"
