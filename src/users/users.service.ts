import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entity/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}



  async create(userData: Partial<User>): Promise<User> {
    const existingUser = await this.userRepo.findOne({
      where: { email: userData.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    if (!userData.password) {
      throw new Error('Password is required');
    }
  
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const user = this.userRepo.create({ ...userData, password: hashedPassword });
    return this.userRepo.save(user);
  }
  

  async findById(id: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { id } });
  }
  
  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email } });
  }
  
  async update(id: string, data: Partial<User>): Promise<User | null> {
    await this.userRepo.update(id, data);
    return this.findById(id);
  }
  
  async delete(id: string): Promise<void> {
    await this.userRepo.delete(id);
  }
}
