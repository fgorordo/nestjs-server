import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { AuthDto } from './dto';
import { JwtPayload, Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/user/entities';
import { compareHash } from '../common/helpers';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    private readonly authTokenSecret: string;
    private readonly refreshTokenSecret: string;

    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {
        this.authTokenSecret = this.configService.get('ACCESS_TOKEN_SECRET')
        this.refreshTokenSecret = this.configService.get('REFRESH_TOKEN_SECRET')
    }

    // * Handler {'auth/login'}
    async login(dto: AuthDto): Promise<Tokens> {
        const {id, email} = await this.handleAuthentication(dto);
        const tokens = await this.signTokens(id, email);
        await this.userService.updateRtHash(id, tokens.refresh_token);
        return tokens;
    }

    // * Handler {'auth/refresh'}
    async refresh(user: User): Promise<Tokens | never> {
        await this.validateRefresh(user);
        const tokens = await this.signTokens(user.id, user.email);
        await this.userService.updateRtHash(user.id, tokens.refresh_token)
        return tokens;

    }

    // * Handler {'auth/logout'}
    async logout(user: User): Promise<void> {
        return this.userService.clearRtHash(user.id);
    }

    // Handle all the user athentication process
    private async handleAuthentication(dto: AuthDto): Promise<User | never> {
        const candidate = await this.userService.getUserAuthenticationData(dto.email);

        if (!candidate) throw new BadRequestException();
        if (!await compareHash(dto.password, candidate.password)) throw new BadRequestException();
        if (!candidate.isActive) throw new ForbiddenException();

        delete candidate.password;
        delete candidate.isActive;

        return candidate;
    }

    // Handle all the token signature process
    private async signTokens(sub: string, email: string): Promise<Tokens> {
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync({sub,email}, {expiresIn: 60 * 15, secret: this.authTokenSecret}),
            this.jwtService.signAsync({sub,email}, {expiresIn: 60 * 60 * 24 * 7, secret: this.refreshTokenSecret}),
        ]);

        return {
            access_token: accessToken,
            refresh_token: refreshToken,
        }
    }

    // Handle all refresh token validation process
    private async validateRefresh(user: User): Promise<void> {
        const candidate = await this.userService.getRefreshAuthenticationData(user.id)
        
        if (!candidate) throw new BadRequestException();
        if (!await compareHash(user.refreshToken, candidate.rtHash)) throw new BadRequestException();
        if (!candidate.isActive) throw new ForbiddenException();

        return;
    }
}
