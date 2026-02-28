const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

const SALT_ROUNDS = 12;

class UserModel {
    static create({ username, email, password }) {
        const id = uuidv4();
        const passwordHash = bcrypt.hashSync(password, SALT_ROUNDS);
        const now = new Date().toISOString();
        db.run(
            'INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
            [id, username, email, passwordHash, now]
        );
        return this.findById(id);
    }

    static findById(id) {
        return db.get('SELECT id, username, email, created_at FROM users WHERE id = ?', [id]);
    }

    static findByEmail(email) {
        return db.get('SELECT * FROM users WHERE email = ?', [email]);
    }

    static findByUsername(username) {
        return db.get('SELECT * FROM users WHERE username = ?', [username]);
    }

    static findByUsernameOrEmail(identifier) {
        return db.get('SELECT * FROM users WHERE email = ? OR username = ?', [identifier, identifier]);
    }

    static verifyPassword(plaintext, hash) {
        return bcrypt.compareSync(plaintext, hash);
    }

    static updateLastLogin(id) {
        db.run('UPDATE users SET last_login = ? WHERE id = ?', [new Date().toISOString(), id]);
    }
}

module.exports = UserModel;
