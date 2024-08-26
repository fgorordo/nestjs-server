import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModuleAsyncOptions } from '@nestjs/typeorm';

export const databaseConfig: TypeOrmModuleAsyncOptions = {
    imports: [ConfigModule],
    inject: [ConfigService],
    useFactory:(configService: ConfigService) => ({
        type: "postgres",
        database: configService.get('DB_NAME'),
        host: configService.get('DB_HOST'),
        username: configService.get('DB_USER'),
        password: configService.get('DB_PASSWORD'),
        port: +configService.get('DB_PORT'),

        autoLoadEntities: true,
        synchronize: true,
    }),
};