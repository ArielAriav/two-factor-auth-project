import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const algorithm = 'aes-256-cbc';
const key = process.env.ENCRYPTION_KEY; 
// Ensure the key is exactly 32 characters long
if (!key || key.length !== 32) {
    throw new Error("ENCRYPTION_KEY must be exactly 32 characters long!");
}

export function encrypt(text) {
    const iv = crypto.randomBytes(16); // Random initialization vector (IV)
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    // Return the IV and encrypted text separated by a colon
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

export function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}