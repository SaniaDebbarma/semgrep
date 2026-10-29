```ts
// apps/api/src/middlewares/authenticate.ts
import { FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import { JWT_PUBLIC_KEY, JWT_ISSUER, JWT_AUDIENCE } from '../config/keys.js';
import type { JwtPayload } from '../services/authService.js';
import { isAccessRevoked } from '../services/accessRevocation.js';

export async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const authHeader = request.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return reply.code(401).send({
      error: 'Unauthorized',
      message: 'Missing or malformed Authorization header. Expected: Bearer <token>',
    });
  }

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }) as JwtPayload & { iat?: number };

    // LB-4: a deactivated staff member's still-unexpired token is refused.
    const revoked = await isAccessRevoked(payload.staffId, payload.iat, (err) =>
      request.log.error({ err }, '[authenticate] revocation check failed; allowing (fail open)')
    );
    if (revoked) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'Session revoked' });
    }

    request.gym = {
      gymId: payload.gymId,
      staffId: payload.staffId,
      role: payload.role,
      country: payload.country,
    };
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'Token expired' });
    }
    if (err instanceof jwt.JsonWebTokenError) {
      return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid token' });
    }
    return reply.code(401).send({ error: 'Unauthorized', message: 'Token verification failed' });
  }
}
```
