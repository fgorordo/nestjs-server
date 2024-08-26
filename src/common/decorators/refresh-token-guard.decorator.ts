import { applyDecorators, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

export function RefreshTokenAuthGuard() {
    return applyDecorators(
        UseGuards(AuthGuard('jwt-refresh'))
    );
};