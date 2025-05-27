import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiResponse } from '../../types/response.type';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let errors: Record<string, string[]> | undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const responseObj = exceptionResponse as any;
        message = responseObj.message || exception.message;

        // Handle validation errors
        if (Array.isArray(responseObj.message)) {
          errors = this.formatValidationErrors(responseObj.message);
          message = 'Validation failed';
        }
      } else {
        message = exceptionResponse as string;
      }
    }

    const errorResponse: ApiResponse = {
      success: false,
      message,
      error: message,
      errors,
      statusCode: status,
      timestamp: new Date().toISOString(),
    };

    response.status(status).json(errorResponse);
  }

  private formatValidationErrors(messages: string[]): Record<string, string[]> {
    const errors: Record<string, string[]> = {};

    messages.forEach((message) => {
      // Parse validation messages like "email must be an email"
      const parts = message.split(' ');
      const field = parts[0];

      if (!errors[field]) {
        errors[field] = [];
      }
      errors[field].push(message);
    });

    return errors;
  }
}
