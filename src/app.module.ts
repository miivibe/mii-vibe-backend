import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { PrismaModule } from './modules/prisma/prisma.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { EmailModule } from './modules/email/email.module';
import { QueueModule } from './modules/queue/queue.module';
import { GlobalAuthGuard } from './modules/auth/guards/global-auth.guard';
import { ScheduleModule } from './modules/schedule/schedule.module';
import { EventModule } from './modules/event/event.module';
import { VoteModule } from './modules/vote/vote.module';
import { MinigameModule } from './modules/minigame/minigame.module';
import { MusicModule } from './modules/music/music.module';
import { NotificationModule } from './modules/notification/notification.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
      inject: [ConfigService],
    }),
    PrismaModule,
    AuthModule,
    UsersModule,
    EmailModule,
    QueueModule,
    ScheduleModule,
    EventModule,
    VoteModule,
    MinigameModule,
    MusicModule,
    NotificationModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: GlobalAuthGuard, // ✅ Global auth guard
    },
  ],
})
export class AppModule {}
