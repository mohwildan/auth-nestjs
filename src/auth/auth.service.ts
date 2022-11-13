import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from '../utils/constants';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;
    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (foundUser) {
      throw new BadRequestException('Email alredy exites');
    }
    const hashedPassword = await this.hashPassword(password);
    await this.prisma.user.create({
      data: {
        email,
        hashPassword: hashedPassword,
      },
    });
    return { message: 'signup was succesfull' };
  }
  async signin(dto: AuthDto, req: Request, res: Response) {
    const { email, password } = dto;
    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (!foundUser) {
      throw new BadRequestException('Wrong Email');
    }
    const isMatch = await this.ComparePassword({
      password,
      hash: foundUser.hashPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Wrong Password');
    }

    const token = await this.signToken({
      id: foundUser.id,
      email: foundUser.email,
    });

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('token', token);
    return res.send({ message: 'Logged in succesfull' });
  }
  async signout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'Logged out succesfull' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltOrRounds);
    return hashedPassword;
  }
  async ComparePassword(args: { password: string; hash: string }) {
    const match = await bcrypt.compare(args.password, args.hash);
    return match;
  }

  async signToken(args: { id: string; email: string }) {
    const payload = args;

    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }
}
