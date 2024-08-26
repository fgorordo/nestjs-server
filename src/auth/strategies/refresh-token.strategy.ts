import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../types';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities';
import { Repository } from 'typeorm';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'refresh-token-secret',
            passReqToCallback: true,
        })
    }

    async validate(req: Request, payload: JwtPayload) {
        const refreshToken = req.get('authorization').replace('Bearer ', '').trim();
        const user = await this.userRepository.findOne({
            where: {
                id: payload.sub
            },
            select: {
                rtHash: true,
                email: true,
                id: true,
                isActive: true,
            }
        });
    
        if (!user)
            throw new UnauthorizedException('')

        if (!user.isActive)
            throw new UnauthorizedException('');

        return {
            ...user,
            refreshToken
        };
    }
}