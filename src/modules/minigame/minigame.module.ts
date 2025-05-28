import { Module } from '@nestjs/common';
import { MinigameService } from './minigame.service';
import { MinigameController } from './minigame.controller';

@Module({
  providers: [MinigameService],
  controllers: [MinigameController]
})
export class MinigameModule {}
