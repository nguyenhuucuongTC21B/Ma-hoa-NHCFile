const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User, Session } = require('../models');
const logger = require('../config/logger');

class AuthController {
  static async register(username, email, password) {
    try {
      const existingUser = await User.findOne({ where: { username } });
      if (existingUser) {
        throw new Error('Username already exists');
      }

      const existingEmail = await User.findOne({ where: { email } });
      if (existingEmail) {
        throw new Error('Email already exists');
      }

      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      const user = await User.create({
        username,
        email,
        passwordHash,
        isVerified: false // Cần xác thực email
      });

      return user;
    } catch (error) {
      logger.error(`Registration error: ${error.message}`);
      throw error;
    }
  }

  static async login(username, password, ipAddress) {
    try {
      const user = await User.findOne({ where: { username } });
      if (!user) {
        throw new Error('Invalid username or password');
      }

      const passwordMatch = await bcrypt.compare(password, user.passwordHash);
      if (!passwordMatch) {
        throw new Error('Invalid username or password');
      }

      // Tạo JWT token
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      // Ghi lại session
      await Session.create({
        userId: user.id,
        token,
        ipAddress,
        userAgent: req.headers['user-agent'],
        expiresAt: new Date(Date.now() + 3600000) // 1 giờ
      });

      // Cập nhật last login
      user.lastLogin = new Date();
      await user.save();

      return { token, user };
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      throw error;
    }
  }

  static async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const session = await Session.findOne({
        where: { token, expiresAt: { [Op.gt]: new Date() } }
      });

      if (!session) {
        throw new Error('Invalid or expired session');
      }

      return decoded;
    } catch (error) {
      logger.error(`Token verification error: ${error.message}`);
      throw error;
    }
  }
}

module.exports = AuthController;