// redis.module.ts
import { Module } from '@nestjs/common';
import Redis from 'ioredis';

@Module({
  providers: [
    {
      provide: 'REDIS',
      useFactory: () => {
        return new Redis(); 
      },
    },
  ],
  exports: ['REDIS'],
})
export class RedisModule {}
