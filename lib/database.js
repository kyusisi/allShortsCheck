import mariadb from "mariadb";

import { hashPassword } from "./auth.js";

const databaseConfig = {
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "allshorts_app",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "allshortscheck",
  connectionLimit: 5,
  timezone: "Z"
};

const pool = mariadb.createPool(databaseConfig);

function firstRow(rows) {
  return rows.length > 0 ? rows[0] : null;
}

export async function initializeDatabase() {
  if (!databaseConfig.password) {
    throw new Error("DB_PASSWORD environment variable is required.");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      login_id VARCHAR(254) NOT NULL,
      email VARCHAR(254) NULL,
      password_salt CHAR(32) NOT NULL,
      password_hash CHAR(128) NOT NULL,
      role ENUM('admin', 'member') NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY users_login_id_unique (login_id),
      UNIQUE KEY users_email_unique (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS invitations (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      email VARCHAR(254) NOT NULL,
      token_hash CHAR(64) NOT NULL,
      invited_by BIGINT UNSIGNED NOT NULL,
      expires_at DATETIME NOT NULL,
      accepted_at DATETIME NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY invitations_email_unique (email),
      UNIQUE KEY invitations_token_hash_unique (token_hash),
      CONSTRAINT invitations_invited_by_fk
        FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      token_hash CHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY user_sessions_token_hash_unique (token_hash),
      KEY user_sessions_expires_at_index (expires_at),
      CONSTRAINT user_sessions_user_id_fk
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  const admin = await getUserByLoginId("admin");

  if (!admin) {
    const password = process.env.ADMIN_PASSWORD;

    if (!password) {
      throw new Error("ADMIN_PASSWORD is required until the initial admin is created.");
    }

    const { salt, hash } = await hashPassword(password);
    await pool.query(
      `
        INSERT INTO users (login_id, email, password_salt, password_hash, role)
        VALUES ('admin', NULL, ?, ?, 'admin')
      `,
      [salt, hash]
    );
  }
}

export async function getUserByLoginId(loginId) {
  const rows = await pool.query(
    `
      SELECT id, login_id, email, password_salt, password_hash, role
      FROM users
      WHERE login_id = ?
      LIMIT 1
    `,
    [loginId]
  );

  return firstRow(rows);
}

export async function getSessionUser(tokenHash) {
  const rows = await pool.query(
    `
      SELECT u.id, u.login_id, u.email, u.role
      FROM user_sessions AS s
      INNER JOIN users AS u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP()
      LIMIT 1
    `,
    [tokenHash]
  );

  return firstRow(rows);
}

export async function createSession(userId, tokenHash, expiresAt) {
  await pool.query(
    `
      INSERT INTO user_sessions (user_id, token_hash, expires_at)
      VALUES (?, ?, ?)
    `,
    [userId, tokenHash, expiresAt]
  );
}

export async function deleteSession(tokenHash) {
  await pool.query("DELETE FROM user_sessions WHERE token_hash = ?", [tokenHash]);
}

export async function createInvitation({ email, tokenHash, invitedBy, expiresAt }) {
  const existingUser = await pool.query(
    "SELECT id FROM users WHERE email = ? LIMIT 1",
    [email]
  );

  if (existingUser.length > 0) {
    return { alreadyRegistered: true };
  }

  await pool.query(
    `
      INSERT INTO invitations (email, token_hash, invited_by, expires_at, accepted_at)
      VALUES (?, ?, ?, ?, NULL)
      ON DUPLICATE KEY UPDATE
        token_hash = VALUES(token_hash),
        invited_by = VALUES(invited_by),
        expires_at = VALUES(expires_at),
        accepted_at = NULL
    `,
    [email, tokenHash, invitedBy, expiresAt]
  );

  return { alreadyRegistered: false };
}

export async function getInvitation(tokenHash) {
  const rows = await pool.query(
    `
      SELECT email, expires_at
      FROM invitations
      WHERE token_hash = ?
        AND accepted_at IS NULL
        AND expires_at > UTC_TIMESTAMP()
      LIMIT 1
    `,
    [tokenHash]
  );

  return firstRow(rows);
}

export async function acceptInvitation({ tokenHash, password }) {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const invitationRows = await connection.query(
      `
        SELECT id, email
        FROM invitations
        WHERE token_hash = ?
          AND accepted_at IS NULL
          AND expires_at > UTC_TIMESTAMP()
        LIMIT 1
        FOR UPDATE
      `,
      [tokenHash]
    );
    const invitation = firstRow(invitationRows);

    if (!invitation) {
      await connection.rollback();
      return null;
    }

    const existingUserRows = await connection.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [invitation.email]
    );

    if (existingUserRows.length > 0) {
      await connection.rollback();
      return null;
    }

    const { salt, hash } = await hashPassword(password);
    const result = await connection.query(
      `
        INSERT INTO users (login_id, email, password_salt, password_hash, role)
        VALUES (?, ?, ?, ?, 'member')
      `,
      [invitation.email, invitation.email, salt, hash]
    );

    await connection.query(
      "UPDATE invitations SET accepted_at = UTC_TIMESTAMP() WHERE id = ?",
      [invitation.id]
    );
    await connection.commit();

    return {
      id: Number(result.insertId),
      loginId: invitation.email,
      email: invitation.email,
      role: "member"
    };
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}
