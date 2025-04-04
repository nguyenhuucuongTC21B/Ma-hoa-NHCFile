const express = require('express');
const https = require('https');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Sequelize } = require('sequelize');
const winston = require('winston');

// Khởi tạo ứng dụng
const app = express();

// Middleware cơ bản
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 100 // giới hạn mỗi IP 100 requests mỗi cửa sổ thời gian
});
app.use(limiter);

// Cấu hình logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Kết nối database
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: msg => logger.info(msg)
});

// Import routes
const authRoutes = require('./routes/auth');
const kmsRoutes = require('./routes/kms');
const cryptoRoutes = require('./routes/crypto');

// Sử dụng routes
app.use('/api/auth', authRoutes);
app.use('/api/kms', kmsRoutes);
app.use('/api/crypto', cryptoRoutes);

// Xử lý lỗi
app.use((err, req, res, next) => {
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
  res.status(err.status || 500).json({ error: err.message });
});

// Khởi động server với HTTPS
const port = process.env.PORT || 443;
https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
}, app).listen(port, () => {
  logger.info(`Server running on port ${port}`);
});