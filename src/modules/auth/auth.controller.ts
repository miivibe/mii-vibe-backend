import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  UseGuards,
  Get,
  BadRequestException
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService, LoginRequest } from './auth.service';
import { SendOtpDto, LoginDto, VerifyOtpDto } from './dto/auth.dto';
import { Public } from '../../common/decorators/public.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginData: LoginDto, @Req() req: Request) {
    const clientInfo = this.extractClientInfo(req);

    const loginRequest: LoginRequest = {
      email: loginData.email,
      password: loginData.password,
      otp: loginData.otp,
      deviceFingerprint: loginData.deviceFingerprint,
      rememberMe: loginData.rememberMe || false,
    };

    return this.authService.login(loginRequest, clientInfo);
  }

  @Public()
  @Post('send-otp')
  @HttpCode(HttpStatus.OK)
  async sendOtp(@Body() sendOtpData: SendOtpDto, @Req() req: Request) {
    const clientInfo = this.extractClientInfo(req);
    return this.authService.sendOtpForLogin(sendOtpData.email, clientInfo);
  }

  @Public()
  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(@Body() verifyOtpData: VerifyOtpDto, @Req() req: Request) {
    const clientInfo = this.extractClientInfo(req);

    const loginRequest: LoginRequest = {
      email: verifyOtpData.email,
      otp: verifyOtpData.otp,
      deviceFingerprint: verifyOtpData.deviceFingerprint,
      rememberMe: verifyOtpData.rememberMe || false,
    };

    return this.authService.login(loginRequest, clientInfo);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() { refreshToken }: { refreshToken: string }, @Req() req: Request) {
    const clientInfo = this.extractClientInfo(req);
    return this.authService.refreshToken(refreshToken, clientInfo);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() { email }: { email: string }, @Req() req: Request) {
    const clientInfo = this.extractClientInfo(req);
    return this.authService.forgotPassword(email, clientInfo);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body() { email, otp, newPassword }: { email: string; otp: string; newPassword: string },
    @Req() req: Request
  ) {
    const clientInfo = this.extractClientInfo(req);
    return this.authService.resetPassword(email, otp, newPassword, clientInfo);
  }

  @Get('verify')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async verifyAuth(@Req() req: Request) {
    const userId = (req as any).user?.sub;
    const user = await this.authService.getUserProfile(userId);

    return {
      message: 'Token is valid',
      data: user,
    };
  }

  private extractClientInfo(req: Request) {
    return {
      ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      deviceFingerprint: req.get('X-Device-Fingerprint'),
      countryCode: req.get('X-Country-Code'),
      city: req.get('X-City'),
    };
  }
}