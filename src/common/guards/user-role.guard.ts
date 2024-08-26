import { Reflector } from '@nestjs/core';
import { CanActivate, ExecutionContext, Injectable, BadRequestException, ForbiddenException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtPayload } from 'src/auth/types';
import { META_ROLES } from '../decorators';
import { UserRoles } from 'src/user/interfaces';
import { User } from 'src/user/entities';

@Injectable()
export class UserRoleGuard implements CanActivate {
  
  constructor(
    private readonly reflector: Reflector
  ) {}

  canActivate(context: ExecutionContext,): boolean | Promise<boolean> | Observable<boolean> {
    const validRoles: UserRoles[] = this.reflector.get( META_ROLES , context.getHandler() )

    if ( !validRoles ) return true;
    if ( validRoles.length === 0 ) return true;
    
    const req = context.switchToHttp().getRequest();
    const user = req.user as User;

    if ( !user ) 
      throw new BadRequestException();
    
    for (const role of validRoles ) {
      if ( user.roles.includes( role ) ) {
        return true;
      }
    }
    
    throw new ForbiddenException();
  }
}
