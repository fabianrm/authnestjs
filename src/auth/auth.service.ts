import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException, } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

import { CreateUserDto, UpdateUserDto, LoginDto, RegisterUserDto } from './dto/index';
import * as bcryptjs from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto; //Destructuramos para no retornar el password

      // 1. Encriptarla clave
      const newUser = new this.userModel({
        ...userData,
        password: bcryptjs.hashSync(password, 10),
      });
      // 2. Guardar el usuario
      return await newUser.save();
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} ya existe`);
      }
      throw new InternalServerErrorException('Ha ocurrido un error interno!!');
    }
  }

  //Retorna usuario creado con Token
  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerDto);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id }),
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Credenciales no validas');
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credenciales no validas');
    }

    const { password: _, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  //Genera un token
  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
