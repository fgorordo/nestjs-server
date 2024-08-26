import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository, UpdateResult } from 'typeorm';
import { generateHash } from 'src/common/helpers';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UserService {

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}
  
  async getUserAuthenticationData(email: string): Promise<User> {
    return await this.userRepository.findOne({
      where: {email},
      select: {
        id: true,
        isActive: true,
        email: true,
        password: true,
      }
    });
  }

  async getRefreshAuthenticationData(id: string): Promise<User> {
    return await this.userRepository.findOne({
      where: {id},
      select: {
        rtHash: true,
        isActive: true,
      }
    });
  }

  async updateRtHash(id: string, payload: string): Promise<void> {
    const rtHash = await generateHash(payload);
    await this.userRepository.update({id}, {rtHash});
    return;
  }

  async clearRtHash(id: string):Promise<void> {
    await this.userRepository.update({id}, {rtHash: null});
    return;
  }
}
