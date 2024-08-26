import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthDto {
    @IsString()
    @IsNotEmpty({message: 'Por favor ingeresa tu correo elctrónico.'})
    @IsEmail({},{message: 'Desbes ingreasar un correo electrónico válido.'})
    email: string;

    @IsString()
    @IsNotEmpty({message: 'Debes ingresar una contraseña.'})
    @MinLength(6, {message: 'La contraseña debe contener al menos 6 caracteres.'})
    password: string;
};