// Set encryption key for tests (before the code runs)
process.env.ENCRYPTION_KEY = '12345678901234567890123456789012'; // exactly 32 characters

import { encrypt, decrypt } from "../src/utils/crypto.js";
import speakeasy from "speakeasy";

describe('Critical Components Security Tests', () => {

    // --- Encryption module tests ---
    describe('Encryption Module', () => {
        test('Should encrypt and decrypt text correctly', () => {
            const originalText = "MySecretPassword123";
            
            // 1. Try to encrypt
            const encrypted = encrypt(originalText);
            
            // Check: encrypted text should not equal the original
            expect(encrypted).not.toBe(originalText);
            // Check: format should include IV (colon separator)
            expect(encrypted).toContain(':');

            // 2. Try to decrypt
            const decrypted = decrypt(encrypted);
            
            // Check: decrypted text must match the original
            expect(decrypted).toBe(originalText);
        });
    });

    // --- 2FA component tests ---
    describe('2FA Logic (Speakeasy)', () => {
        test('Should verify a valid token correctly', () => {
            // 1. Generate a temporary secret
            const secret = speakeasy.generateSecret();
            
            // 2. Generate a token (as if from the user's app)
            const token = speakeasy.totp({
                secret: secret.base32,
                encoding: 'base32'
            });

            // 3. Verify the server can validate it
            const verified = speakeasy.totp.verify({
                secret: secret.base32,
                encoding: 'base32',
                token: token,
                window: 1
            });

            expect(verified).toBe(true);
        });

        test('Should reject an invalid token', () => {
            const secret = speakeasy.generateSecret();
            
            // Create an invalid token
            const wrongToken = "000000";

            const verified = speakeasy.totp.verify({
                secret: secret.base32,
                encoding: 'base32',
                token: wrongToken,
                window: 1
            });

            expect(verified).toBe(false);
        });
    });
});