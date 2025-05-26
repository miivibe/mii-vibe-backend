import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport';

export interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    // ✅ Sửa createTransporter thành createTransport
    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST'),
      port: parseInt(this.configService.get<string>('SMTP_PORT') || '587'), // ✅ Thêm default value
      secure: false, // true for 465, false for other ports
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_PASS'),
      },
    } as SMTPTransport.Options); // ✅ Type assertion để tránh lỗi TypeScript
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    const mailOptions = {
      from: this.configService.get<string>('SMTP_FROM'),
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text,
    };

    await this.transporter.sendMail(mailOptions);
  }

  generateOtpEmailTemplate(email: string, otp: string, type: string): string {
    const templates = {
      login_2fa: {
        subject: 'Mã xác thực đăng nhập - Miichisoft',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Mã xác thực đăng nhập</h2>
            <p>Xin chào <strong>${email}</strong>,</p>
            <p>Mã OTP của bạn để đăng nhập vào hệ thống Miichisoft là:</p>
            <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
              <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
            </div>
            <p><strong>Lưu ý:</strong> Mã này có hiệu lực trong 5 phút.</p>
            <p>Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email này.</p>
            <hr>
            <p style="color: #666; font-size: 12px;">© 2025 Miichisoft. All rights reserved.</p>
          </div>
        `
      },
      password_reset: {
        subject: 'Mã đặt lại mật khẩu - Miichisoft',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Đặt lại mật khẩu</h2>
            <p>Xin chào <strong>${email}</strong>,</p>
            <p>Mã OTP để đặt lại mật khẩu của bạn là:</p>
            <div style="background: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0;">
              <h1 style="color: #dc3545; font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
            </div>
            <p><strong>Lưu ý:</strong> Mã này có hiệu lực trong 5 phút.</p>
            <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
            <hr>
            <p style="color: #666; font-size: 12px;">© 2025 Miichisoft. All rights reserved.</p>
          </div>
        `
      }
    };

    return templates[type] || templates.login_2fa;
  }
}
