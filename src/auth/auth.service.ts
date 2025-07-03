import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    public jwtService: JwtService, 
  ) {}

  async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid email or password');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new UnauthorizedException('Invalid email or password');

    const { password: _, ...result } = user;
    return result;
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);

    const payload = { sub: user.id, email: user.email, roles: user.roles };

    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async refreshToken(user: any) {
    const payload = { sub: user.id, email: user.email, roles: user.roles };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
