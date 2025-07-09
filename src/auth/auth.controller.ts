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
  
    // Check user session or token - here assuming JWT in cookie or header
    const token = req.headers.authorization?.split(' ')[1];
  
    if (!token) {
      // User NOT logged in: redirect to login page with original params
      const loginUrl = `http://localhost:3000?redirect_uri=${encodeURIComponent(
        redirectUri,
      )}&client_id=${clientId}`;
      return res.redirect(loginUrl);
    }
  
    try {
      const payload = this.authService.jwtService.verify(token);
  
      // Generate authorization code
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
  
      // Redirect user to SP callback with code
      return res.redirect(`${redirectUri}?code=${code}`);
    } catch {
      // Invalid token, redirect to login page again
      const loginUrl = `http://localhost:4000/login?redirect_uri=${encodeURIComponent(
        redirectUri,
      )}&client_id=${clientId}`;
      return res.redirect(loginUrl);
    }
  }
  
  @Post('token')
  async exchangeCode(
    @Body() body: { code: string; client_id: string; redirect_uri: string },
  ) {
    const raw = await this.redis.get(`web_code:${body.code}`);
  
    if (!raw) throw new UnauthorizedException('Invalid or expired code');
  
    const stored = JSON.parse(raw);
  
    if (stored.client_id !== body.client_id || stored.redirect_uri !== body.redirect_uri) {
      throw new UnauthorizedException('Invalid client or redirect URI');
    }
  
    await this.redis.del(`web_code:${body.code}`);
  
    const payload = {
      sub: stored.user.sub,     
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

