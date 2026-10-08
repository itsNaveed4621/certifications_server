import { env } from "../../config/env";
import { Otp } from "../../models/otp.model";
import { Profile } from "../../models/profile.model";
import { UserProgress } from "../../models/progress.model";
import { Settings } from "../../models/settings.model";
import { IUser, User } from "../../models/user.model";
import { ApplicantService } from "../../services/applicant.service";
import { LoopsService } from "../../services/loops.service";
import { ApiError } from "../../utils/api-error";
import { compareHash, generateOtp, hashValue } from "../../utils/crypto";
import { signAccessToken } from "../../utils/jwt";

const OTP_EXPIRY_MINUTES = 10;
const MAX_OTP_ATTEMPTS = 5;

// Built-in allowed test/demo accounts for QA & design review
const DEFAULT_ALLOWED_EMAILS = [
  "amara@okonkwo.xyz",
  "ada@nwosu.energy",
  "demo@siherdefi.org",
  "test@siherdefi.org",
];

export class AuthService {
  /**
   * Only registered applicants or allowed cohort users may claim their seat and receive an OTP.
   */
  static async claimSeat(rawEmail: string) {
    const email = rawEmail.trim().toLowerCase();

    // 1. Check if user is already in local database
    let user = await User.findOne({ email });

    // 2. Check if user is in allowed environment emails or defaults
    const isAllowedEmail =
      env.allowedEmails.includes(email) ||
      DEFAULT_ALLOWED_EMAILS.includes(email);

    // 3. Check if user submitted an application in SI3 CMS
    const applicant = !user ? await ApplicantService.findByEmail(email) : null;

    // If not found anywhere, reject access!
    if (!user && !isAllowedEmail && !applicant) {
      throw ApiError.badRequest(
        "This email is not registered for Si Her DeFi. Please enter the email address you used to apply."
      );
    }

    // If user does not exist locally yet, create user record
    if (!user) {
      user = await User.create({
        email,
        role: "member",
        isEmailVerified: false,
      });

      // Pre-fill profile from application data or demo data
      const prefillName = applicant?.name || (email.includes("amara") ? "Amara Rodrigues" : "");
      const prefillRole = applicant?.role || (email.includes("amara") ? "Product Lead" : "");
      const prefillOrg = applicant?.organization || (email.includes("amara") ? "Ecosystem Builder" : "");
      const prefillSocial = applicant?.socialLink || "";

      const prefilledFields = [
        prefillName ? "name" : null,
        prefillRole ? "role" : null,
        prefillOrg ? "organization" : null,
        prefillSocial ? "socialLink" : null,
      ].filter(Boolean) as string[];

      await Profile.create({
        user: user._id,
        name: prefillName,
        role: prefillRole,
        organization: prefillOrg,
        socialLink: prefillSocial,
        bio: email.includes("amara")
          ? "Building payment rails for small merchants. Here to understand stablecoins properly before I ship anything on-chain."
          : "",
        prefilledFields,
      });
    }

    const plainOtp = generateOtp(6);
    const hashedCode = await hashValue(plainOtp);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    // Remove any older OTP for this email
    await Otp.deleteMany({ email });

    await Otp.create({
      email,
      hashedCode,
      attempts: 0,
      expiresAt,
    });

    // Dispatch real email via Loops.so
    const loopsResult = await LoopsService.sendOtpEmail(email, plainOtp);

    // The plain code is only ever printed locally — never into production logs
    if (env.NODE_ENV === "development") {
      console.log(`🔑 [AUTH] 6-digit OTP for ${email}: ${plainOtp}`);
    }
    if (loopsResult.success) {
      console.log(`📨 [LOOPS] Sign-in code emailed to ${email}`);
    } else if (loopsResult.error) {
      console.warn(`⚠️ [LOOPS] Sign-in code NOT emailed to ${email}: ${loopsResult.error}`);
    }

    return {
      email,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
      loopsSent: loopsResult.success,
      // In development, return devCode for streamlined browser/E2E testing
      ...(env.NODE_ENV === "development" ? { devCode: plainOtp } : {}),
    };
  }

  static async verifyOtp(rawEmail: string, code: string) {
    const email = rawEmail.trim().toLowerCase();
    const otpRecord = await Otp.findOne({ email });

    // Mongo's TTL sweep can lag up to a minute, so check expiry ourselves too
    if (!otpRecord || otpRecord.expiresAt.getTime() <= Date.now()) {
      if (otpRecord) await Otp.deleteOne({ _id: otpRecord._id });
      throw ApiError.badRequest("Verification code has expired or was not requested. Please request a new code.");
    }

    if (otpRecord.attempts >= MAX_OTP_ATTEMPTS) {
      await Otp.deleteOne({ _id: otpRecord._id });
      throw ApiError.tooManyRequests("Maximum verification attempts exceeded. Please request a new code.");
    }

    const isMatch = await compareHash(code, otpRecord.hashedCode);

    if (!isMatch) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      const remainingAttempts = MAX_OTP_ATTEMPTS - otpRecord.attempts;
      throw ApiError.badRequest(`Incorrect verification code. ${remainingAttempts} attempts remaining.`);
    }

    // OTP is valid - clean it up
    await Otp.deleteOne({ _id: otpRecord._id });

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, role: "member", isEmailVerified: true });
    } else {
      user.isEmailVerified = true;
      user.lastLoginAt = new Date();
      await user.save();
    }

    // Ensure Profile exists
    let profile = await Profile.findOne({ user: user._id });
    if (!profile) {
      const applicant = await ApplicantService.findByEmail(email);
      const prefillName = applicant?.name || (email.includes("amara") ? "Amara Rodrigues" : "");
      const prefillRole = applicant?.role || (email.includes("amara") ? "Product Lead" : "");
      const prefillOrg = applicant?.organization || (email.includes("amara") ? "Ecosystem Builder" : "");
      const prefillSocial = applicant?.socialLink || "";

      profile = await Profile.create({
        user: user._id,
        name: prefillName,
        role: prefillRole,
        organization: prefillOrg,
        socialLink: prefillSocial,
        bio: email.includes("amara")
          ? "Building payment rails for small merchants. Here to understand stablecoins properly before I ship anything on-chain."
          : "",
        prefilledFields: [
          prefillName ? "name" : null,
          prefillRole ? "role" : null,
          prefillOrg ? "organization" : null,
          prefillSocial ? "socialLink" : null,
        ].filter(Boolean),
      });
    }

    // Ensure UserProgress exists
    let progress = await UserProgress.findOne({ user: user._id });
    if (!progress) {
      // Starts empty — badges are earned only by passing module quizzes
      progress = await UserProgress.create({
        user: user._id,
        completedModules: [],
        earnedBadges: [],
      });
    }

    // Ensure Settings exists
    let settings = await Settings.findOne({ user: user._id });
    if (!settings) {
      settings = await Settings.create({ user: user._id });
    }

    const token = this.generateToken(user);

    return {
      token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        walletAddress: user.walletAddress,
        isEmailVerified: user.isEmailVerified,
      },
      profile: {
        name: profile.name,
        role: profile.role,
        organization: profile.organization,
        socialLink: profile.socialLink,
        bio: profile.bio,
        photoUrl: profile.photoUrl,
        prefilledFields: profile.prefilledFields,
      },
    };
  }

  static async resendOtp(email: string) {
    return this.claimSeat(email);
  }

  static generateToken(user: IUser): string {
    return signAccessToken(user);
  }

  /** Ends every session of this learner — all previously issued tokens stop working. */
  static async logout(user: IUser) {
    await User.updateOne({ _id: user._id }, { $inc: { tokenVersion: 1 } });
  }
}
