import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Cấu hình CORS chi tiết
  app.enableCors({
    origin: [
      'http://localhost:3000',  // NextJS dev
      'http://localhost:3001',  // NextJS dev alternative
      'http://192.168.1.6:3000',
      'http://192.168.1.6:3001',
      'https://your-frontend-domain.com',  // Production domain
      'https://your-app.vercel.app',  // Vercel deployment
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Device-Fingerprint',
      'X-Country-Code',
      'X-City',
      'Accept',
      'Origin',
      'X-Requested-With'
    ],
    credentials: true,  // Cho phép cookies/auth headers
    optionsSuccessStatus: 200,  // Cho IE11
    preflightContinue: false,
  });

  // Global pipes, filters, interceptors
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: false,
    transform: true,
    transformOptions: {
      enableImplicitConversion: true,
    },
  }));

  app.useGlobalInterceptors(new ResponseInterceptor());
  app.useGlobalFilters(new HttpExceptionFilter());

  // Global prefix
  app.setGlobalPrefix('api');

  const port = process.env.PORT || 3001;
  await app.listen(port);
  console.log(`🚀 Backend running on http://localhost:${port}`);
}
bootstrap();
