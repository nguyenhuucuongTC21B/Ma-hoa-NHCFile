require('dotenv').config();
const express = require('express');
const { sequelize } = require('./models');

const app = express();
app.use(express.json());

// Kết nối database
sequelize.authenticate()
  .then(() => console.log('DB connected'))
  .catch(err => console.error('DB connection error:', err));

// Routes
app.use('/api/auth', require('./api/auth'));
app.use('/api/keys', require('./api/keys'));

app.listen(process.env.PORT || 3001, () => {
  console.log(`Auth service running on port ${process.env.PORT}`);
});