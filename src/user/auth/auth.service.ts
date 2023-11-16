import { Injectable, ConflictException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from "bcryptjs";
import { UserType } from "@prisma/client";

interface SignupParams {
    name: string;
    email: string;
    phone: string;
    password: string;
}

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService) { }
    async signup({ email, password, name, phone }: SignupParams) {
        const userExists = await this.prismaService.user.findUnique({
            where: {
                email
            }
        });
        if (userExists) {
            throw new ConflictException()
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await this.prismaService.user.create({
            data: {
                email,
                name,
                phone,
                password: hashedPassword,
                user_type: UserType.BUYER
            }
        });
        return user;
    }
}
