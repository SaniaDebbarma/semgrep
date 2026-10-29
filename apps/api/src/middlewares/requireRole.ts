```ts
// apps/api/src/middlewares/requireRole.ts
import { FastifyRequest, FastifyReply } from 'fastify';
import { StaffRole } from '@revmetiq/db';

/**
 * Factory that returns a preHandler enforcing role-based access.
 * Always use AFTER `authenticate` — relies on req.gym being populated.
 *
 * Usage:
 * { preHandler: [authenticate, requireRole([StaffRole.owner, StaffRole.manager])] }
 */
export function requireRole(allowedRoles: StaffRole[]) {
  return async function roleGuard(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (!request.gym) {
      // Defensive: authenticate should always run first
      return reply.code(401).send({ error: 'Unauthorized', message: 'Not authenticated' });
    }

    if (!allowedRoles.includes(request.gym.role)) {
      return reply.code(403).send({
        error: 'Forbidden',
        message: `Role '${request.gym.role}' is not permitted. Required: ${allowedRoles.join(', ')}`,
      });
    }
  };
}
```
