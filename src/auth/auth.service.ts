import { BadRequestException, Body, ForbiddenException, Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { AuthDto } from './dto';
import { compareHash, generateHash } from './helpers';
import { JwtPayload, Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/user/entities';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
    ){}
    
    async localSignIn(dto: AuthDto): Promise<Tokens> {
        const user = await this.validateCredentials(dto);
        const tokens = await this.generateAuthTokens(user.id, user.email)
        await this.updateRefreshTokenHash(user.id, tokens.refresh_token);
        
        return tokens;
    }

    async logout(id: string): Promise<void> {
        await this.userService.clearRefreshTokenHash(id);
        return;
    }

    async refresh(user: User) {
        if (!compareHash(user.refreshToken, user.rtHash))
            throw new ForbiddenException();
        const tokens = await this.generateAuthTokens(user.id, user.email);
        await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

        return tokens;
    }

    private async validateCredentials(dto: AuthDto): Promise<User> {
        const candidate = await this.userService.findByEmail(dto.email);

        if (!candidate)
            throw new BadRequestException('Invalid credentials');

        if(!compareHash(dto.password, candidate.password))
            throw new BadRequestException('Invalid credentials');
        
        return candidate;
    }

    private async generateAuthTokens(sub: string, email: string): Promise<Tokens> {
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync({sub,email}, {expiresIn: 60 * 15, secret: 'access-token-secret'}),
            this.jwtService.signAsync({sub,email}, {expiresIn: 60 * 60 * 24 * 7, secret: 'refresh-token-secret'}),
        ])

        return {
            access_token: accessToken,
            refresh_token: refreshToken,
        }
    }


    private async updateRefreshTokenHash(userId: string, refreshToken: string) {
        const hash = await generateHash(refreshToken)
        await this.userService.updateRefreshTokenHash(userId,hash);
    }

    private async validateRefreshToken(user: User, refreshToken: string) {
    }


}
