import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;

export function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

export function isValidPassword(password) {
  return typeof password === "string" && password.length >= 10 && password.length <= 128;
}

export async function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const derivedKey = await scrypt(password, salt, 64);

  return {
    salt,
    hash: derivedKey.toString("hex")
  };
}

export async function verifyPassword(password, salt, expectedHash) {
  const derivedKey = await scrypt(password, salt, 64);
  const expectedKey = Buffer.from(expectedHash, "hex");

  return (
    expectedKey.length === derivedKey.length &&
    timingSafeEqual(expectedKey, derivedKey)
  );
}

export function createOpaqueToken() {
  return randomBytes(32).toString("base64url");
}

export function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}
