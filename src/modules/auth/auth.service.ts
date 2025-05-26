import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { FailureReason, OtpType, EventType, Severity } from '../../types/auth.types';
import { QueueService } from '../queue/queue.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

export interface LoginRequest {
  email: string;
  password?: string;
  otp?: string;
  deviceFingerprint?: string;
  rememberMe?: boolean;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: any;
  requiresOtp?: boolean;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private queueService: QueueService,
  ) {}

  async login(loginData: LoginRequest, clientInfo: any): Promise<LoginResponse> {
    const { email, password, otp, deviceFingerprint, rememberMe = false } = loginData;
    const { ipAddress, userAgent, countryCode, city } = clientInfo;

    // Kiểm tra rate limiting
    await this.checkRateLimit(email, ipAddress);

    // Tìm user
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        sessions: true,
        loginAttempts: {
          where: { attemptedAt: { gte: new Date(Date.now() - 15 * 60 * 1000) } },
          orderBy: { attemptedAt: 'desc' }
        }
      }
    });

    if (!user) {
      await this.logFailedAttempt(undefined, email, FailureReason.INVALID_CREDENTIALS, clientInfo);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Kiểm tra account status
    await this.checkAccountStatus(user);

    // Xác thực bước 1: Password
    if (password) {
      const isPasswordValid = await this.validatePassword(password, user.passwordHash, user.salt);
      if (!isPasswordValid) {
        await this.incrementFailedAttempts(user);
        await this.logFailedAttempt(user.id, email, FailureReason.INVALID_CREDENTIALS, clientInfo);
        throw new UnauthorizedException('Invalid credentials');
      }

      // Reset failed attempts
      await this.resetFailedAttempts(user);

      // Kiểm tra 2FA
      if (user.twoFactorEnabled) {
        await this.sendOtp(user, OtpType.LOGIN_2FA, clientInfo);
        return { requiresOtp: true } as LoginResponse;
      }
    }

    // Xác thực bước 2: OTP (nếu có)
    if (user.twoFactorEnabled && otp) {
      const isOtpValid = await this.validateOtp(user.id, otp, OtpType.LOGIN_2FA);
      if (!isOtpValid) {
        await this.logFailedAttempt(user.id, email, FailureReason.INVALID_2FA, clientInfo);
        throw new UnauthorizedException('Invalid OTP');
      }
    }

    // Tạo session và tokens
    const session = await this.createSession(user, clientInfo, rememberMe);
    const tokens = await this.generateTokens(user, session.id);

    // Log successful login
    await this.logSuccessfulLogin(user, clientInfo);

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: this.sanitizeUser(user),
    };
  }

  async sendOtpForLogin(email: string, clientInfo: any): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    await this.sendOtp(user, OtpType.LOGIN_2FA, clientInfo);
    return { message: 'OTP sent successfully' };
  }

  async refreshToken(refreshToken: string, clientInfo: any): Promise<{ accessToken: string }> {
    try {
      const payload = this.jwtService.verify(refreshToken);
      const session = await this.prisma.userSession.findUnique({
        where: { id: payload.sessionId },
        include: { user: true }
      });

      if (!session || !session.refreshExpiresAt || session.refreshExpiresAt < new Date()) {
        throw new UnauthorizedException('Refresh token expired');
      }

      const newAccessToken = this.jwtService.sign({
        sub: session.user.id,
        email: session.user.email,
        sessionId: session.id
      }, { expiresIn: '15m' });

      return { accessToken: newAccessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(sessionId: string): Promise<{ message: string }> {
    await this.prisma.userSession.delete({
      where: { id: sessionId }
    });
    return { message: 'Logged out successfully' };
  }

  async logoutAll(userId: number): Promise<{ message: string }> {
    await this.prisma.userSession.deleteMany({
      where: { userId }
    });
    return { message: 'Logged out from all devices' };
  }

  async getUserProfile(userId: number): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        phone: true,
        isActive: true,
        isVerified: true,
        twoFactorEnabled: true,
        createdAt: true,
        lastLoginAt: true
      }
    });
    return user;
  }

  async getUserSessions(userId: number): Promise<any[]> {
    const sessions = await this.prisma.userSession.findMany({
      where: { userId },
      select: {
        id: true,
        deviceFingerprint: true,
        ipAddress: true,
        userAgent: true,
        countryCode: true,
        city: true,
        createdAt: true,
        lastActivity: true,
        isRememberMe: true
      },
      orderBy: { lastActivity: 'desc' }
    });
    return sessions;
  }

  async changePassword(userId: number, currentPassword: string, newPassword: string, clientInfo: any): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const isCurrentPasswordValid = await this.validatePassword(currentPassword, user.passwordHash, user.salt);
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(newPassword + salt, 12);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash,
        salt,
        passwordChangedAt: new Date()
      }
    });

    await this.logSecurityEvent(userId, EventType.PASSWORD_CHANGED, Severity.MEDIUM, 'Password changed successfully');
    return { message: 'Password changed successfully' };
  }

  async forgotPassword(email: string, clientInfo: any): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      // Don't reveal if user exists
      return { message: 'If the email exists, a reset code has been sent' };
    }

    await this.sendOtp(user, OtpType.PASSWORD_RESET, clientInfo);
    return { message: 'If the email exists, a reset code has been sent' };
  }

  async resetPassword(email: string, otp: string, newPassword: string, clientInfo: any): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invalid reset code');
    }

    const isOtpValid = await this.validateOtp(user.id, otp, OtpType.PASSWORD_RESET);
    if (!isOtpValid) {
      throw new UnauthorizedException('Invalid or expired reset code');
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(newPassword + salt, 12);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        salt,
        passwordChangedAt: new Date()
      }
    });

    await this.logSecurityEvent(user.id, EventType.PASSWORD_CHANGED, Severity.MEDIUM, 'Password reset successfully');
    return { message: 'Password reset successfully' };
  }

  // Private methods
  private async validatePassword(password: string, hash: string, salt: string): Promise<boolean> {
    const hashedPassword = await bcrypt.hash(password + salt, 12);
    return hashedPassword === hash;
  }

  private async checkAccountStatus(user: any): Promise<void> {
    if (!user.isActive) {
      throw new UnauthorizedException('Account is inactive');
    }

    if (user.isLocked) {
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        throw new UnauthorizedException('Account is temporarily locked');
      } else if (user.lockedUntil && user.lockedUntil <= new Date()) {
        await this.prisma.user.update({
          where: { id: user.id },
          data: {
            isLocked: false,
            lockedUntil: null,
            failedLoginAttempts: 0
          }
        });
      }
    }
  }

  private async checkRateLimit(email: string, ipAddress: string): Promise<void> {
    const recentAttempts = await this.prisma.loginAttempt.count({
      where: {
        OR: [
          { email, attemptedAt: { gte: new Date(Date.now() - 15 * 60 * 1000) } },
          { ipAddress, attemptedAt: { gte: new Date(Date.now() - 15 * 60 * 1000) } }
        ]
      }
    });

    if (recentAttempts > 10) {
      throw new BadRequestException('Too many login attempts. Please try again later.');
    }
  }

  private async incrementFailedAttempts(user: any): Promise<void> {
    const updatedUser = await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: { increment: 1 },
        lastFailedLogin: new Date()
      }
    });

    if (updatedUser.failedLoginAttempts >= 5) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          isLocked: true,
          lockedUntil: new Date(Date.now() + 30 * 60 * 1000)
        }
      });

      await this.logSecurityEvent(user.id, EventType.ACCOUNT_LOCKED, Severity.HIGH,
        'Account locked due to multiple failed login attempts');
    }
  }

  private async resetFailedAttempts(user: any): Promise<void> {
    if (user.failedLoginAttempts > 0) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: 0,
          lastFailedLogin: null
        }
      });
    }
  }

  private async sendOtp(user: any, type: OtpType, clientInfo: any): Promise<void> {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = await bcrypt.hash(code, 10);

    await this.prisma.otpCode.create({
      data: {
        userId: user.id,
        code,
        codeHash,
        type,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
        ipAddress: clientInfo.ipAddress,
        deviceFingerprint: clientInfo.deviceFingerprint,
      }
    });

    await this.queueService.addOtpEmailJob(user.email, code, type);

    console.log(`OTP for ${user.email}: ${code}`);
  }

  private async validateOtp(userId: number, code: string, type: OtpType): Promise<boolean> {
    const otpRecord = await this.prisma.otpCode.findFirst({
      where: {
        userId,
        type,
        isUsed: false,
        expiresAt: { gt: new Date() }
      }
    });

    if (!otpRecord || otpRecord.attempts >= otpRecord.maxAttempts) {
      return false;
    }

    const isValid = await bcrypt.compare(code, otpRecord.codeHash);

    await this.prisma.otpCode.update({
      where: { id: otpRecord.id },
      data: {
        attempts: { increment: 1 },
        ...(isValid && {
          isUsed: true,
          usedAt: new Date()
        })
      }
    });

    return isValid;
  }

  private async createSession(user: any, clientInfo: any, rememberMe: boolean): Promise<any> {
    const sessionId = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date(Date.now() + (rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000));

    return await this.prisma.userSession.create({
      data: {
        id: sessionId,
        userId: user.id,
        expiresAt,
        refreshExpiresAt: rememberMe ? new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) : expiresAt,
        deviceFingerprint: clientInfo.deviceFingerprint,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        countryCode: clientInfo.countryCode,
        city: clientInfo.city,
        isRememberMe: rememberMe,
      }
    });
  }

  private async generateTokens(user: any, sessionId: string): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = {
      sub: user.id,
      email: user.email,
      sessionId
    };

    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    return { accessToken, refreshToken };
  }

  private async logFailedAttempt(userId: number | undefined, email: string, reason: FailureReason, clientInfo: any): Promise<void> {
    await this.prisma.loginAttempt.create({
      data: {
        userId: userId ?? null,
        email,
        isSuccessful: false,
        failureReason: reason,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        deviceFingerprint: clientInfo.deviceFingerprint,
        countryCode: clientInfo.countryCode,
        city: clientInfo.city,
      }
    });
  }

  private async logSuccessfulLogin(user: any, clientInfo: any): Promise<void> {
    await this.prisma.loginAttempt.create({
      data: {
        userId: user.id,
        email: user.email,
        isSuccessful: true,
        ipAddress: clientInfo.ipAddress,
        userAgent: clientInfo.userAgent,
        deviceFingerprint: clientInfo.deviceFingerprint,
        countryCode: clientInfo.countryCode,
        city: clientInfo.city,
      }
    });

    await this.logSecurityEvent(user.id, EventType.LOGIN_SUCCESS, Severity.LOW,
      'User logged in successfully');
  }

  private async logSecurityEvent(userId: number, eventType: EventType, severity: Severity, description: string): Promise<void> {
    await this.prisma.securityEvent.create({
      data: {
        userId,
        eventType,
        severity,
        description,
      }
    });
  }

  private sanitizeUser(user: any): any {
    const { passwordHash, salt, twoFactorSecret, twoFactorBackupCodes, ...sanitized } = user;
    return sanitized;
  }
}