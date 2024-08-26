import { ValidationPipeOptions } from '@nestjs/common';

export const globalValidationPipeConfig: ValidationPipeOptions = {
    stopAtFirstError: true,
    whitelist: true,
    forbidNonWhitelisted: true
}
