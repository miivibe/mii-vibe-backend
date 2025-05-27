import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import { IS_PUBLIC_KEY } from '../../../common/decorators/public.decorator';

@Injectable()
export class GlobalAuthGuard {
  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Access token is required');
    }

    try {
      const payload = this.jwtService.verify(token);

      // Verify session
      const session = await this.prisma.userSession.findUnique({
        where: { id: payload.sessionId },
        include: { user: true }
      });

      if (!session || session.expiresAt < new Date()) {
        throw new UnauthorizedException('Session expired');
      }

      if (!session.user.isActive) {
        throw new UnauthorizedException('Account is inactive');
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
      throw new UnauthorizedException('Invalid access token');
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
