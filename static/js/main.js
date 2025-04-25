document.addEventListener('DOMContentLoaded', function() {
    // Password visibility toggle
    const togglePasswordBtns = document.querySelectorAll('.toggle-password');
    togglePasswordBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordField = document.getElementById(targetId);
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                this.innerHTML = '<i class="fa fa-eye-slash"></i>';
            } else {
                passwordField.type = 'password';
                this.innerHTML = '<i class="fa fa-eye"></i>';
            }
        });
    });
    
    // Copy to clipboard functionality
    const copyBtns = document.querySelectorAll('.copy-btn');
    copyBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-clipboard-text');
            const originalText = this.innerHTML;
            
            // Copy to clipboard
            navigator.clipboard.writeText(textToCopy).then(function() {
                // Update button text temporarily
                btn.innerHTML = '<i class="fa fa-check"></i> Copied!';
                
                // Revert button text after 2 seconds
                setTimeout(function() {
                    btn.innerHTML = originalText;
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy text: ', err);
                btn.innerHTML = '<i class="fa fa-times"></i> Failed!';
                
                setTimeout(function() {
                    btn.innerHTML = originalText;
                }, 2000);
            });
        });
    });
    
    // Generated password copy functionality
    const generatedPasswordEl = document.getElementById('generated-password');
    const copyGeneratedBtn = document.getElementById('copy-generated');
    
    if (generatedPasswordEl && copyGeneratedBtn) {
        copyGeneratedBtn.addEventListener('click', function() {
            const textToCopy = generatedPasswordEl.textContent;
            
            navigator.clipboard.writeText(textToCopy).then(function() {
                copyGeneratedBtn.innerHTML = '<i class="fa fa-check"></i> Copied!';
                
                setTimeout(function() {
                    copyGeneratedBtn.innerHTML = '<i class="fa fa-copy"></i> Copy';
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy text: ', err);
                copyGeneratedBtn.innerHTML = '<i class="fa fa-times"></i> Failed!';
                
                setTimeout(function() {
                    copyGeneratedBtn.innerHTML = '<i class="fa fa-copy"></i> Copy';
                }, 2000);
            });
        });
    }
    
    // Auto-update password strength indicator
    const passwordInput = document.querySelector('.password-strength-check');
    const strengthIndicator = document.getElementById('password-strength');
    
    if (passwordInput && strengthIndicator) {
        passwordInput.addEventListener('input', async function() {
            const password = this.value;
            
            if (password.length > 0) {
                try {
                    // You could implement a client-side version of the strength check
                    // or make an API call to the server
                    let strength = "Weak";
                    
                    if (password.length >= 12 && 
                        /[a-z]/.test(password) && 
                        /[A-Z]/.test(password) && 
                        /[0-9]/.test(password) && 
                        /[^a-zA-Z0-9]/.test(password)) {
                        strength = "Very Strong";
                    } else if (password.length >= 10 && 
                              (/[a-z]/.test(password) && /[A-Z]/.test(password)) && 
                              (/[0-9]/.test(password) || /[^a-zA-Z0-9]/.test(password))) {
                        strength = "Strong";
                    } else if (password.length >= 8 && 
                              ((/[a-z]/.test(password) && /[A-Z]/.test(password)) || 
                               /[0-9]/.test(password) || 
                               /[^a-zA-Z0-9]/.test(password))) {
                        strength = "Medium";
                    }
                    
                    // Update the indicator text and color
                    strengthIndicator.textContent = strength;
                    strengthIndicator.className = 'strength-' + strength.toLowerCase().replace(' ', '-');
                } catch (error) {
                    console.error('Error evaluating password strength:', error);
                }
            } else {
                strengthIndicator.textContent = '';
            }
        });
    }
    
    // Confirm password deletion
    const deletePasswordForm = document.getElementById('delete-password-form');
    if (deletePasswordForm) {
        deletePasswordForm.addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to delete this password? This action cannot be undone.')) {
                e.preventDefault();
            }
        });
    }
    
    // Password generator toggle
    const generatePasswordToggle = document.getElementById('generate-password-toggle');
    const passwordGenerationOptions = document.getElementById('password-generation-options');
    const passwordLengthInput = document.querySelector('input[name="password_length"]');
    const passwordLengthDisplay = document.getElementById('password-length-display');
    
    if (generatePasswordToggle && passwordGenerationOptions) {
        // Show/hide password generation options
        generatePasswordToggle.addEventListener('change', function() {
            if (this.checked) {
                passwordGenerationOptions.style.display = 'block';
            } else {
                passwordGenerationOptions.style.display = 'none';
            }
        });
        
        // Initialize state
        passwordGenerationOptions.style.display = generatePasswordToggle.checked ? 'block' : 'none';
    }
    
    // Update password length display when slider changes
    if (passwordLengthInput && passwordLengthDisplay) {
        passwordLengthInput.addEventListener('input', function() {
            passwordLengthDisplay.textContent = this.value;
        });
        
        // Set initial value
        if (passwordLengthInput.value) {
            passwordLengthDisplay.textContent = passwordLengthInput.value;
        }
    }
});
