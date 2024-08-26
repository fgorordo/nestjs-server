import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { JwtPayload, Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { GetUser } from 'src/common/decorators';
import { User } from 'src/user/entities';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  localSignIn(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.localSignIn(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  logout(@GetUser() user: User): Promise<void> {
    return this.authService.logout(user.id);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  refreshTokens(
    @GetUser() user: User,
  ){
    return this.authService.refresh(user);
  }
}
