import mongoose from "mongoose";
import bcryptjs from "bcryptjs";
import validator from "validator";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [50, "Name cannot exceed 50 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      validate: [validator.isEmail, "Please provide a valid email"],
      index: true, // For fast login lookup
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
      select: false, // Don't include password in queries by default
    },
    profilePicture: {
      type: String, // S3 URL or local file path
      default: null,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    accountType: {
      type: String,
      enum: ["free", "premium", "enterprise"],
      default: "free",
    },
    storageUsed: {
      type: Number,
      default: 0, // in bytes
      min: [0, "Storage used cannot be negative"],
    },
    storageLimit: {
      type: Number,
      default: function() {
        // Set storage limits based on account type
        switch (this.accountType) {
          case "free":
            return 5 * 1024 * 1024 * 1024; // 5 GB
          case "premium":
            return 50 * 1024 * 1024 * 1024; // 50 GB
          case "enterprise":
            return 500 * 1024 * 1024 * 1024; // 500 GB
          default:
            return 5 * 1024 * 1024 * 1024; // 5 GB
        }
      },
      min: [0, "Storage limit cannot be negative"],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
      select: false,
    },
    emailVerificationExpires: {
      type: Date,
      select: false,
    },
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpires: {
      type: Date,
      select: false,
    },
    lastLoginAt: {
      type: Date,
      default: null,
    },
    loginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: {
      type: Date,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    refreshTokens: [{
      token: {
        type: String,
        required: true,
      },
      createdAt: {
        type: Date,
        default: Date.now,
        expires: 2592000, // 30 days
      },
    }],
    // File and folder references
    rootFolder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Folder",
    },
    // User preferences
    preferences: {
      theme: {
        type: String,
        enum: ["light", "dark", "system"],
        default: "system",
      },
      language: {
        type: String,
        default: "en",
      },
      emailNotifications: {
        fileShared: { type: Boolean, default: true },
        storageAlmost: { type: Boolean, default: true },
        securityAlerts: { type: Boolean, default: true },
      },
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: function(doc, ret) {
        delete ret.password;
        delete ret.refreshTokens;
        delete ret.emailVerificationToken;
        delete ret.passwordResetToken;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        return ret;
      }
    }
  }
);

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ accountType: 1 });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash password if it's modified
  if (!this.isModified('password')) return next();

  try {
    // Hash password with cost of 12
    const salt = await bcryptjs.genSalt(12);
    this.password = await bcryptjs.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!candidatePassword || !this.password) return false;
  return await bcryptjs.compare(candidatePassword, this.password);
};

// Instance method to handle failed login attempts
userSchema.methods.incLoginAttempts = async function() {
  // Check if we have a previous lock that has expired
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: {
        loginAttempts: 1,
        lockUntil: 1
      }
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };

  // Lock account after 5 failed attempts for 2 hours
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours

  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = {
      lockUntil: Date.now() + lockTime
    };
  }

  return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
  return this.updateOne({
    $unset: {
      loginAttempts: 1,
      lockUntil: 1
    },
    $set: {
      lastLoginAt: new Date()
    }
  });
};

// Instance method to check storage quota
userSchema.methods.hasStorageSpace = function(fileSize) {
  return (this.storageUsed + fileSize) <= this.storageLimit;
};

// Instance method to get storage percentage
userSchema.methods.getStoragePercentage = function() {
  return Math.round((this.storageUsed / this.storageLimit) * 100);
};

// Instance method to add refresh token
userSchema.methods.addRefreshToken = async function(token) {
  // Keep only last 5 refresh tokens
  if (this.refreshTokens.length >= 5) {
    this.refreshTokens = this.refreshTokens.slice(-4);
  }

  this.refreshTokens.push({ token });
  await this.save();
};

// Instance method to remove refresh token
userSchema.methods.removeRefreshToken = async function(token) {
  this.refreshTokens = this.refreshTokens.filter(
    refreshToken => refreshToken.token !== token
  );
  await this.save();
};

// Static method to find user by email
userSchema.statics.findByEmail = function(email) {
  return this.findOne({
    email: email.toLowerCase(),
    isActive: true
  }).select('+password');
};

// Static method to get user statistics
userSchema.statics.getUserStats = async function() {
  const stats = await this.aggregate([
    {
      $group: {
        _id: null,
        totalUsers: { $sum: 1 },
        activeUsers: {
          $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
        },
        premiumUsers: {
          $sum: { $cond: [{ $eq: ['$accountType', 'premium'] }, 1, 0] }
        },
        totalStorageUsed: { $sum: '$storageUsed' },
        averageStorageUsed: { $avg: '$storageUsed' }
      }
    }
  ]);

  return stats[0] || {
    totalUsers: 0,
    activeUsers: 0,
    premiumUsers: 0,
    totalStorageUsed: 0,
    averageStorageUsed: 0
  };
};

export default mongoose.model("User", userSchema);
