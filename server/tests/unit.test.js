// מגדירים מפתח הצפנה לצורך הבדיקה (לפני שהקוד רץ)
process.env.ENCRYPTION_KEY = '12345678901234567890123456789012'; // בדיוק 32 תווים

import { encrypt, decrypt } from "../src/utils/crypto.js";
import speakeasy from "speakeasy";

describe('Critical Components Security Tests', () => {

    // --- בדיקת רכיב ההצפנה ---
    describe('Encryption Module', () => {
        test('Should encrypt and decrypt text correctly', () => {
            const originalText = "MySecretPassword123";
            
            // 1. נסה להצפין
            const encrypted = encrypt(originalText);
            
            // בדיקה: הטקסט המוצפן לא צריך להיות שווה למקור
            expect(encrypted).not.toBe(originalText);
            // בדיקה: הפורמט צריך לכלול IV (סימן נקודתיים)
            expect(encrypted).toContain(':');

            // 2. נסה לפענח
            const decrypted = decrypt(encrypted);
            
            // בדיקה: הטקסט המפעונח חייב להיות זהה למקור
            expect(decrypted).toBe(originalText);
        });
    });

    // --- בדיקת רכיב ה-2FA ---
    describe('2FA Logic (Speakeasy)', () => {
        test('Should verify a valid token correctly', () => {
            // 1. נייצר סוד זמני
            const secret = speakeasy.generateSecret();
            
            // 2. נייצר טוקן (כאילו המשתמש באפליקציה)
            const token = speakeasy.totp({
                secret: secret.base32,
                encoding: 'base32'
            });

            // 3. נבדוק שהשרת יודע לאמת אותו
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
            
            // נמציא טוקן שגוי
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