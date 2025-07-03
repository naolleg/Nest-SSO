import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  Get,
  Query,
  Inject,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import Redis from 'ioredis';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Response, Request as ExpressRequest } from 'express';
import { v4 as uuid } from 'uuid';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    @Inject('REDIS') private redis: Redis,
  ) {}

  @Post('login')
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @UseGuards(JwtAuthGuard)
  @Get('validate')
  validateToken(@Request() req) {
    return req.user; 
  }

  @UseGuards(JwtAuthGuard)
  @Post('refresh')
  async refresh(@Request() req) {
    return this.authService.refreshToken(req.user);
  }

@UseGuards(JwtAuthGuard)
@Get('authorize')
async authorize(
  @Query('redirect_uri') redirectUri: string,
  @Query('client_id') clientId: string,
  @Res() res: Response,
  @Req() req: ExpressRequest,
) {
  const user = req.user;

  const code = uuid();

  // ✅ Store user, client_id, and redirect_uri
  await this.redis.set(
    `code:${code}`,
    JSON.stringify({
      user,
      client_id: clientId,
      redirect_uri: redirectUri,
    }),
    'EX',
    300,
  );



  return res.redirect(`callback?code=${code}`);
}

  @Post('token')
  async exchangeCode(
    @Body() body: { code: string; client_id: string; redirect_uri: string },
  ) {
    const raw = await this.redis.get(`code:${body.code}`);
if (!raw) throw new UnauthorizedException('Invalid or expired code');

const stored = JSON.parse(raw);

// Validate client_id and redirect_uri
if (stored.client_id !== body.client_id || stored.redirect_uri !== body.redirect_uri) {
  throw new UnauthorizedException('Invalid client or redirect URI');
}

    await this.redis.del(`code:${body.code}`);
  
    const payload = {
      sub: stored.user.id,
      email: stored.user.email,
      roles: stored.user.roles,
    };
  
    return {
      access_token: this.authService.jwtService.sign(payload),
      refresh_token: this.authService.jwtService.sign(payload, {
        expiresIn: '30d',
      }),
    };
  }
  
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@Request() req) {
    return req.user;
  }
}

