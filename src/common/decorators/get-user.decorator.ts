import { createParamDecorator, ExecutionContext, InternalServerErrorException } from '@nestjs/common';
import { User } from 'src/user/entities';

export const GetUser = createParamDecorator((data: string, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest();
    const user = req.user as User;
    
    if (!user) throw new InternalServerErrorException('Ooops! Somehting went wrong, please get in touch with support.');
    return (!data)
        ? user
        : user
})