import { Injectable } from '@nestjs/common';
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

  async updateRefreshTokenHash(id: string, payload:string) {
    return await this.userRepository.update({id}, {rtHash: payload})
  }

  async clearRefreshTokenHash(id: string) {
    return await this.userRepository.update({id}, {rtHash: null});
  }

  async findByEmail(email: string) {
    return await this.userRepository.findOneBy({email});
  }

  async findUnique(id: string) {
    return await this.userRepository.findOneBy({id});
  }
}
