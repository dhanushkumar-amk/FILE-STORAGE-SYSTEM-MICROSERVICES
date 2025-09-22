import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
      index: true, // fast login lookup
    },
    password: {
      type: String,
      required: true,
      minlength: 6, // will be hashed in controller
    },
    profilePic: {
      type: String, // S3 URL
      default: null,
    },
    files: [
      {
        fileId: { type: mongoose.Schema.Types.ObjectId, ref: "File" },
      },
    ],
    storageUsed: {
      type: Number,
      default: 0, // in bytes
    },
    storageLimit: {
      type: Number,
      default: 5 * 1024 * 1024 * 1024, // 5 GB default
    },
    accountType: {
      type: String,
      enum: ["free", "premium", "admin"], // you can extend later
      default: "free",
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

// Index for common queries
userSchema.index({ email: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ accountType: 1 });

export default mongoose.model("User", userSchema);
