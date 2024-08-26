import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../types';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities';
import { Repository } from 'typeorm';

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'access-token-secret',
        })
    }

    async validate(payload: JwtPayload) {
        const user = await this.userRepository.findOneBy({id: payload.sub})
        
        if ( !user ) 
            throw new UnauthorizedException('')
            
        if ( !user.isActive ) 
            throw new UnauthorizedException('');

        return user;
    }
}