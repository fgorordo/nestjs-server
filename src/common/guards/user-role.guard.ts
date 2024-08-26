import { Reflector } from '@nestjs/core';
import { CanActivate, ExecutionContext, Injectable, BadRequestException, ForbiddenException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtPayload } from 'src/auth/types';
import { META_ROLES } from '../decorators';
import { UserRoles } from 'src/user/interfaces';

@Injectable()
export class UserRoleGuard implements CanActivate {
  
  constructor(
    private readonly reflector: Reflector
  ) {}

  canActivate(context: ExecutionContext,): boolean | Promise<boolean> | Observable<boolean> {
    const validRoles: string[] = this.reflector.get( META_ROLES , context.getHandler() )

    if ( !validRoles ) return true;
    if ( validRoles.length === 0 ) return true;
    
    const req = context.switchToHttp().getRequest();
    const user = req.user as JwtPayload;

    if ( !user ) 
      throw new BadRequestException();
    
    for (const role of validRoles ) {
      if ( validRoles.includes( role ) ) {
        return true;
      }
    }
    
    throw new ForbiddenException();
  }
}
