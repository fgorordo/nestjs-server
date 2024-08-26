import { applyDecorators, UseGuards } from '@nestjs/common';
import { UserRoles } from 'src/user/interfaces';
import { RoleProtected } from './role-protected.decorator';
import { AuthGuard } from '@nestjs/passport';
import { UserRoleGuard } from '../guards/user-role.guard';
import { AccessTokenGuard } from '../guards';

export function AccessTokenAuthGuard(...roles: UserRoles[]) {
    return applyDecorators(
        RoleProtected(...roles),
        UseGuards(AccessTokenGuard, UserRoleGuard)
    );
};