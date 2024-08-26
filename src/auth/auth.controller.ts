import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AccessTokenAuthGuard, GetUser, RefreshTokenAuthGuard } from 'src/common/decorators';
import { User } from 'src/user/entities';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login(@Body() dto: AuthDto): Promise<Tokens | never> {
    return this.authService.login(dto);
  }

  @RefreshTokenAuthGuard()
  @Post('refresh')
  refreshTokens(@GetUser() user: User): Promise<Tokens | never> {
    return this.authService.refresh(user);
  } 

  @AccessTokenAuthGuard()
  @Post('logout')
  logout(@GetUser() user: User): Promise<void> {
    return this.authService.logout(user);
  }
}
