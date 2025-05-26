import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { EmailJobData } from './email.queue';

@Injectable()
export class QueueService {
  constructor(
    @InjectQueue('email') private emailQueue: Queue<EmailJobData>,
  ) {}

  async addOtpEmailJob(to: string, otp: string, type: string): Promise<void> {
    const emailTemplate = this.generateOtpEmailTemplate(to, otp, type);

    await this.emailQueue.add('send-otp', {
      to,
      subject: emailTemplate.subject,
      html: emailTemplate.html,
      type: 'otp',
    }, {
      attempts: 3, // Retry 3 lần nếu fail
      backoff: {
        type: 'exponential',
        delay: 2000, // Delay 2s, 4s, 8s
      },
      removeOnComplete: 10, // Giữ lại 10 job thành công
      removeOnFail: 50, // Giữ lại 50 job thất bại
    });
  }

  async addNotificationEmailJob(to: string, subject: string, html: string): Promise<void> {
    await this.emailQueue.add('send-notification', {
      to,
      subject,
      html,
      type: 'welcome',
    }, {
      attempts: 2,
      backoff: {
        type: 'fixed',
        delay: 1000,
      },
      delay: 1000,
    });
  }

  private generateOtpEmailTemplate(email: string, otp: string, type: string) {
    const templates = {
      'LOGIN_2FA': {
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
      'PASSWORD_RESET': {
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

    return templates[type] || templates['LOGIN_2FA'];
  }
}
