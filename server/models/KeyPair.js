module.exports = (sequelize, DataTypes) => {
  const KeyPair = sequelize.define('KeyPair', {
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'Users',
        key: 'id'
      }
    },
    publicKey: {
      type: DataTypes.TEXT,
      allowNull: false
    },
    privateKeyEncrypted: {
      type: DataTypes.TEXT,
      allowNull: false
    },
    keyAlgorithm: {
      type: DataTypes.STRING,
      defaultValue: 'RSA-OAEP'
    },
    keySize: {
      type: DataTypes.INTEGER,
      defaultValue: 2048
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true
    }
  });

  KeyPair.associate = models => {
    KeyPair.belongsTo(models.User, { foreignKey: 'userId' });
  };

  return KeyPair;
};