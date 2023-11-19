import { Injectable, ConflictException, HttpException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from "bcryptjs";
import { UserType } from "@prisma/client";
import * as jwt from "jsonwebtoken";

interface SignupParams {
    name: string;
    email: string;
    phone: string;
    password: string;
}

interface SigninParams {
    email: string;
    password: string;
}

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService) { }
    async signup({ email, password, name, phone }: SignupParams, userType: UserType) {
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
                user_type: userType
            }
        });
        return this.generateJWT(user.name, user.id)
    }
    async signIn({ email, password }: SigninParams) {
        const user = await this.prismaService.user.findUnique({
            where: {
                email
            }
        });
        if (!user) {
            throw new HttpException("Invalid credentials", 400);
        }
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            throw new HttpException("Invalid credentials", 400);
        }
        return this.generateJWT(user.name, user.id);
    }
    private generateJWT(name: string, id: number) {
        return jwt.sign({
            name,
            id,
        }, process.env.JWT_SECRET_KEY, { expiresIn: '7d' })
    }
    generateProductKey(email: string, userType: UserType) {
        const string = `${email}-${userType}-${process.env.PRODUCT_SECRET_KEY}`;
        return bcrypt.hash(string, 10)
    }
}
