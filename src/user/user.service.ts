import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { isNotEmpty } from 'class-validator';

@Injectable()
export class UserService {

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  create(createUserDto: CreateUserDto) {
    const candidate = this.userRepository.create(createUserDto);
    const user = this.userRepository.save(candidate);
    return user;
  }

  async getLoginCredentials(email: string) {
    const user = await this.userRepository.findOne({
      where: {email},
      select: {
        password: true,
        isActive: true,
        id: true,
        email: true,
      }
    })

    if (!user) throw new BadRequestException();
    
    return user;
  }

  async getRefreshTokenHash(id: string): Promise<User> {
    return await this.userRepository.findOne({
      where: {id},
      select: {
        id: true,
        rtHash: true,
        email: true,
      }
    })
  }

  async updateRefreshTokenHash(id: string, payload:string) {
    return await this.userRepository.update({id}, {rtHash: payload})
  }

  async clearRefreshTokenHash(id: string) {
    return await this.userRepository.update({id}, {rtHash: null});
  }
}
