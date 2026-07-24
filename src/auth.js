"use strict";

const jwt = require("jsonwebtoken");
const { db } = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
if (!process.env.JWT_SECRET) {
  console.warn(
      "[golf-buds-backend] WARNING: JWT_SECRET is not set. Using an insecure default. " +
            "Set JWT_SECRET in your environment before deploying anywhere real."
              );
              }

              function signToken(userId) {
                return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "30d" });
                }

                function requireAuth(req, res, next) {
                  const header = req.headers.authorization || "";
                    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
                      if (!token) return res.status(401).json({ error: "Missing or invalid Authorization header" });
                        try {
                            const payload = jwt.verify(token, JWT_SECRET);
                                const stillExists = db.prepare("SELECT 1 FROM users WHERE id = ?").get(payload.sub);
                                    if (!stillExists) return res.status(401).json({ error: "This account no longer exists" });
                                        req.userId = payload.sub;
                                            next();
                                              } catch (e) {
                                                  return res.status(401).json({ error: "Invalid or expired token" });
                                                    }
                                                    }

                                                    module.exports = { signToken, requireAuth };
                                                    
