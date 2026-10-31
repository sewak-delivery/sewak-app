import crypto from "node:crypto";
import { query } from "./db.js";

const hash = value => crypto.createHash("sha256").update(value + process.env.JWT_SECRET).digest("hex");

export async function sendOtp(phone, code) {
  // Development-only transport. Never use console OTP in production.
  if (process.env.OTP_PROVIDER === "console" && process.env.NODE_ENV !== "production") {
    console.log(`[SEWAK DEV OTP] ${phone}: ${code}`);
    return;
  }
  // Integrate an SMS provider such as MSG91, Twilio, or an Indian DLT-approved provider here.
  // Do not return OTP codes from production API responses.
  throw new Error("SMS provider is not configured. Configure a production OTP provider first.");
}
export async function createOtp(phone) {
  const recent = await query(
    "SELECT COUNT(*)::int AS n FROM otp_codes WHERE phone=$1 AND created_at > NOW() - INTERVAL '15 minutes'",
    [phone]
  );
  if (recent.rows[0].n >= 5) throw new Error("Too many OTP requests. Try again later.");
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  await query("INSERT INTO otp_codes(phone, code_hash, expires_at) VALUES($1,$2,NOW()+($3 || ' minutes')::interval)",
    [phone, hash(code), String(Number(process.env.OTP_TTL_MINUTES || 5))]);
  await sendOtp(phone, code);
}
export async function verifyOtp(phone, code) {
  const result = await query(
    "SELECT id, code_hash, attempts FROM otp_codes WHERE phone=$1 AND consumed_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1",
    [phone]
  );
  const otp = result.rows[0];
  if (!otp || otp.attempts >= 5) return false;
  await query("UPDATE otp_codes SET attempts=attempts+1 WHERE id=$1", [otp.id]);
  if (hash(code) !== otp.code_hash) return false;
  await query("UPDATE otp_codes SET consumed_at=NOW() WHERE id=$1", [otp.id]);
  return true;
}
