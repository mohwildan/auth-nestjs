import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { Request } from 'express';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}
  async getMyUser(id: string, req: Request) {
    const user = await this.prisma.user.findUnique({ where: { id } });

    if (!user) {
      throw new NotFoundException();
    }

    const decodedUser = req.user as { id: string; email: string };
    console.log(decodedUser);
    if (user.id !== decodedUser.id) {
      throw new ForbiddenException();
    }
    return { user };
  }
  async getUsers() {
    const users = await this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
      },
    });
    return users;
  }
}
