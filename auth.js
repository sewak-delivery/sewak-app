import jwt from "jsonwebtoken";
import { query } from "./db.js";

export function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, phone: user.phone }, process.env.JWT_SECRET, { expiresIn: "7d" });
}
export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Login required" });
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const result = await query("SELECT id, phone, name, role, active FROM users WHERE id=$1", [payload.sub]);
    const user = result.rows[0];
    if (!user || !user.active) return res.status(401).json({ error: "Account unavailable" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}
export function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: "Not allowed" });
    next();
  };
}
