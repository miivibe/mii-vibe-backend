import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Token không tồn tại');
    }

    try {
      const payload = this.jwtService.verify(token);

      // Kiểm tra session còn valid không
      const session = await this.prisma.userSession.findUnique({
        where: { id: payload.sessionId },
        include: { user: true }
      });

      if (!session || session.expiresAt < new Date()) {
        throw new UnauthorizedException('Session đã hết hạn');
      }

      if (!session.user.isActive) {
        throw new UnauthorizedException('Tài khoản đã bị vô hiệu hóa');
      }

      // Update last activity
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { lastActivity: new Date() }
      });

      request.user = {
        sub: payload.sub,
        email: payload.email,
        sessionId: payload.sessionId,
      };

      return true;
    } catch (error) {
      throw new UnauthorizedException('Token không hợp lệ');
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
