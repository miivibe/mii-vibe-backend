import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bull';
import { EmailService, EmailOptions } from '../email/email.service';
import { Injectable, Logger } from '@nestjs/common';

export interface EmailJobData {
  to: string;
  subject: string;
  html: string;
  text?: string;
  type: 'otp' | 'welcome' | 'password_reset';
}

@Injectable()
@Processor('email')
export class EmailProcessor {
  private readonly logger = new Logger(EmailProcessor.name);

  constructor(private emailService: EmailService) {}

  @Process('send-otp')
  async handleSendOtp(job: Job<EmailJobData>) {
    this.logger.log(`Processing email job ${job.id} for ${job.data.to}`);

    try {
      await this.emailService.sendEmail({
        to: job.data.to,
        subject: job.data.subject,
        html: job.data.html,
        text: job.data.text,
      });

      this.logger.log(`Email sent successfully to ${job.data.to}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${job.data.to}:`, error);
      throw error; // Bull sẽ retry job nếu có lỗi
    }
  }

  @Process('send-notification')
  async handleSendNotification(job: Job<EmailJobData>) {
    this.logger.log(`Processing notification email ${job.id}`);

    try {
      await this.emailService.sendEmail({
        to: job.data.to,
        subject: job.data.subject,
        html: job.data.html,
        text: job.data.text,
      });

      this.logger.log(`Notification email sent successfully`);
    } catch (error) {
      this.logger.error(`Failed to send notification email:`, error);
      throw error;
    }
  }
}
