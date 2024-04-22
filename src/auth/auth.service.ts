import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register.dto';

@Injectable()
export class AuthService {


  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData,
      });

      await newUser.save();

      const { password: _, ...user } = newUser.toJSON();

      return user;

    } catch (error) {

      if (error.code === 11000) {
        throw new BadRequestException(`User with email ${createUserDto.email} already exists`);
      }

      throw new InternalServerErrorException('Something went wrong!');
    }


  }

  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create(registerDto);

    return {
      user,
      token: this.getJwtToken({ id: user._id })
    }

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials - email');
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Invalid credentials - password');
    }

    const { password: _, ...userData } = user.toJSON();

    return {
      user: userData,
      token: this.getJwtToken({ id: user.id })
    }
  }

  findAll() {
   return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);

    const { password: _, ...userData } = user.toJSON();

    return userData;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
