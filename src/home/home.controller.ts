import { Controller, Delete, Get, Post, Put, Query, Param, ParseIntPipe, Body, UnauthorizedException, UseGuards } from '@nestjs/common';
import { HomeService } from './home.service';
import { CreateHomeDto, HomeResponseDto, UpdateHomeDto, InquireDto } from './dto/home.dto';
import { PropertyType, UserType } from '@prisma/client';
import { User, UserInfo } from 'src/user/decorators/user.decorator';
import { Roles } from 'src/decorators/roles.decorator';

@Controller('home')
export class HomeController {
    constructor(private readonly homeService: HomeService) { }
    @Get()
    getHomes(
        @Query('city') city?: string,
        @Query('minPrice') minPrice?: string,
        @Query('maxPrice') maxPrice?: string,
        @Query('propertyType') propertyType?: PropertyType
    ): Promise<HomeResponseDto[]> {
        const price = minPrice || maxPrice ? {
            ...(minPrice && { gte: parseFloat(minPrice) }),
            ...(maxPrice && { lte: parseFloat(maxPrice) }),
        } : undefined;
        const filters = {
            ...(city && { city }),
            ...(price && { price }),
            ...(propertyType && { propertyType }),

        };
        return this.homeService.getHomes(filters);
    }
    @Get(':id')
    getHome(@Param('id', ParseIntPipe) id: number) {
        return this.homeService.getHomeById(id);
    }

    @Roles(UserType.REALTOR, UserType.ADMIN)
    @Post()
    createHome(@Body() body: CreateHomeDto, @User() user: UserInfo) {
        return this.homeService.createHome(body, user.id);
    }

    @Put(':id')
    async updateHome(
        @Param('id', ParseIntPipe) id: number,
        @Body() body: UpdateHomeDto,
        @User() user: UserInfo,
    ) {
        const realtor = await this.homeService.getRealtorByHomeId(id);

        if (realtor.id !== user.id) {
            throw new UnauthorizedException();
        }

        return this.homeService.updateHomeById(id, body);
    }

    @Delete(':id')
    async deleteHome(
        @Param('id', ParseIntPipe) id: number,
        @User() user: UserInfo,
    ) {
        const realtor = await this.homeService.getRealtorByHomeId(id);

        if (realtor.id !== user.id) {
            throw new UnauthorizedException();
        }
        return this.homeService.deleteHomeById(id);
    }
    @Roles(UserType.BUYER)
    @Post('/:id/inquire')
    inquire(
        @Param('id', ParseIntPipe) homeId: number,
        @User() user: UserInfo,
        @Body() { message }: InquireDto,
    ) {
        return this.homeService.inquire(user, homeId, message);
    }

    @Roles(UserType.REALTOR)
    @Get('/:id/messages')
    async getHomeMessages(
        @Param('id', ParseIntPipe) id: number,
        @User() user: UserInfo,
    ) {
        const realtor = await this.homeService.getRealtorByHomeId(id);

        if (realtor.id !== user.id) {
            throw new UnauthorizedException();
        }
        return this.homeService.getMessagesByHome(id);
    }
}

