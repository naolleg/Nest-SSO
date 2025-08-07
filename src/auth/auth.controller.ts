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
  BadRequestException,
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

  @Get('validate')
  validateToken(@Request() req) {
    return req.user; 
  }

  @UseGuards(JwtAuthGuard)
  @Post('refresh')
  async refresh(@Request() req) {
    return this.authService.refreshToken(req.user);
  }
  
  @Get('authorize')
async authorize(
  @Query('redirect_uri') redirectUri: string,
  @Query('client_id') clientId: string,
  @Req() req: ExpressRequest,
  @Res() res: Response,
) {
  if (!redirectUri || !clientId) {
    throw new BadRequestException('Missing redirect_uri or client_id');
  }

  const token =
    req.headers.authorization?.split(' ')[1] ||
    req.cookies?.access_token;

  if (!token) {
    const loginUrl = `http://localhost:3000?redirect_uri=${encodeURIComponent(
      redirectUri,
    )}&client_id=${clientId}`;
    return res.redirect(loginUrl);
  }

  try {
    const payload = this.authService.jwtService.verify(token);
    const code = uuid();

    await this.redis.set(
      `web_code:${code}`,
      JSON.stringify({
        user: payload,
        client_id: clientId,
        redirect_uri: redirectUri,
      }),
      'EX',
      300,
    );

    return res.redirect(`${redirectUri}?code=${code}`);
  } catch (err) {
    const loginUrl = `http://localhost:4000/login?redirect_uri=${encodeURIComponent(
      redirectUri,
    )}&client_id=${clientId}`;
    return res.redirect(loginUrl);
  }
}


@Post('token')
async exchangeCode(
  @Body() body: { code: string; client_id: string; redirect_uri: string },
  @Res({ passthrough: true }) res: Response, 
) {
  const raw = await this.redis.get(`web_code:${body.code}`);

  if (!raw) throw new UnauthorizedException('Invalid or expired code');

  const stored = JSON.parse(raw);

  if (
    stored.client_id !== body.client_id ||
    stored.redirect_uri !== body.redirect_uri
  ) {
    throw new UnauthorizedException('Invalid client or redirect URI');
  }

  await this.redis.del(`web_code:${body.code}`);

  const payload = {
    sub: stored.user.sub,
    name: stored.user.name,
    email: stored.user.email,
    roles: stored.user.roles,
    
  };

  const access_token = this.authService.jwtService.sign(payload);
  const refresh_token = this.authService.jwtService.sign(payload, {
    expiresIn: '30d',
  });


  res.cookie('access_token', access_token, {
    httpOnly: true,
    secure: true, 
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7, 
  });

  res.cookie('refresh_token', refresh_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30, 
  });

  return { message: 'Login successful' };
}

  
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@Request() req) {
    return req.user;
  }
}

