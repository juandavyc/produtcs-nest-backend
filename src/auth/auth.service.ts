import { BadRequestException, Injectable, InternalServerErrorException, Param, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create.user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import * as bcrypts from 'bcryptjs'
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt.payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register.user.dto';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) {

  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    // 1- encriptar la contraseña
    // 2- guardar el usuario
    // 3- generar el token
    // 4- excepciones
    try {
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcrypts.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const { password: passwordNo, ...user } = newUser.toJSON();
      return user;

    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException(`something terrible happened`)
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {

    const registerUser = await this.create(registerUserDto);

    return {
      user: registerUser,
      token: this.getJwtToken({ id: registerUser._id })
    };
  }

  async LoginDto(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email')
    }
    if (!bcrypts.compareSync(password, user.password)) {
      throw new UnauthorizedException('No valid credentials - password')
    }

    const { password: passwordNo, ...userData } = user.toJSON();
    return {
      user: userData,
      token: this.getJwtToken({ id: user.id })
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }
  async findUserById(id:string){
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();
    return rest;
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
    const token = this.jwtService.sign(payload);
    return token;
  }
}
