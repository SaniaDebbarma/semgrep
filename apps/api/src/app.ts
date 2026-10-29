```ts
// apps/api/src/app.ts (Security & Plugin Bootstrap Slice)
import './instrument.js';
import 'dotenv/config.js';
import * as Sentry from '@sentry/node';
import requestContext from '@fastify/request-context';
import Fastify, { type FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import compress from '@fastify/compress';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import { redis } from './config/redis.js';
import { validateEnv } from './config/env.js';
import { registerSwagger } from './config/swagger.js';
import { auditLogHook } from './middlewares/auditLog.js';
import { requireBasicAuth } from './middlewares/basicAuth.js';
import { registerErrorHandler } from './plugins/errorHandler.js';
import { registerProcessErrorHandlers } from './plugins/processErrorHandlers.js';

declare module '@fastify/request-context' {
  interface RequestContextData {
    requestId: string;
    gymId: string | null;
  }
}

registerProcessErrorHandlers();
validateEnv();

const server = Fastify({
  ajv: {
    customOptions: {
      keywords: ['example'],
    },
  },
  logger: buildHttpLoggerOptions(process.env),
  trustProxy: true,
});

server.decorateRequest('gym', null as never);

const PRODUCTION_ORIGINS: readonly string[] = [
  '[https://app.revmetiqos.com](https://app.revmetiqos.com)',
  '[https://revmetiqos.com](https://revmetiqos.com)',
  '[https://www.revmetiqos.com](https://www.revmetiqos.com)',
];

function buildCorsOrigin(
  origin: string | undefined,
  callback: (err: Error | null, allow: boolean) => void
): void {
  if (!origin) {
    callback(null, true);
    return;
  }
  if (PRODUCTION_ORIGINS.includes(origin)) {
    callback(null, true);
  } else {
    const err = Object.assign(new Error(`CORS: Origin '${origin}' is not permitted.`), {
      statusCode: 403,
    });
    callback(err, false);
  }
}

async function buildApp() {
  Sentry.setupFastifyErrorHandler(server, {
    shouldHandleError: (error, _request, reply) => {
      const status = (error as { statusCode?: number }).statusCode ?? reply.statusCode ?? 500;
      return status >= 500;
    },
  });

  server.setNotFoundHandler((request, reply) => {
    return reply.code(404).send({
      error: 'Not Found',
      message: `Route ${request.method} ${request.url} does not exist. API routes are served under /api/v1.`,
      statusCode: 404,
    });
  });

  await server.register(requestContext, {
    hook: 'onRequest',
    defaultStoreValues: {
      requestId: 'unknown',
      gymId: null as string | null,
    },
  });

  // Pre-parser Content-Type allowlist
  server.addHook('onRequest', async (request, reply) => {
    const METHODS_WITH_BODY = new Set(['POST', 'PUT', 'PATCH']);
    if (!METHODS_WITH_BODY.has(request.method)) return;

    const raw = request.headers['content-type'];
    if (!raw) return;

    const mediaType = raw.split(';')[0]!.trim().toLowerCase();
    const ALLOWED = new Set([
      'application/json',
      'multipart/form-data',
      'application/x-www-form-urlencoded',
    ]);

    if (!ALLOWED.has(mediaType)) {
      return reply.code(415).send({
        error: 'Unsupported Media Type',
        message: `This API accepts ${[...ALLOWED].join(', ')}.`,
        statusCode: 415,
      });
    }
  });

  server.addHook('onRequest', async (request) => {
    request.requestContext.set('requestId', request.id);
    const gymId = (request as FastifyRequest & { gym: { id: string } | null }).gym?.id ?? null;
    if (gymId) {
      request.requestContext.set('gymId', gymId);
      request.log = request.log.child({ gymId });
    }
  });

  // Security headers (OWASP hardened)
  await server.register(helmet, {
    global: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },
    noSniff: true,
    frameguard: { action: 'deny' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
      useDefaults: false,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    dnsPrefetchControl: { allow: false },
    ieNoOpen: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  });

  server.addHook('onSend', async (_request, reply) => {
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  });

  // CORS
  await server.register(cors, {
    origin: process.env.NODE_ENV === 'production' ? buildCorsOrigin : true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Idempotency-Key'],
    credentials: true,
    maxAge: 3600,
  });

  await server.register(compress, {
    global: true,
    encodings: ['br', 'gzip'],
    threshold: 1024,
  });

  // Cookie parser (HttpOnly refresh token)
  await server.register(cookie, {
    secret: process.env.COOKIE_SECRET ?? 'revmetiq-cookie-secret-change-in-prod',
  });

  // Multipart (CSV ingestion limits)
  await server.register(multipart, {
    attachFieldsToBody: false,
    limits: {
      files: 1,
      fileSize: 10 * 1024 * 1024,
      fields: 0,
    },
  });

  // Global rate limit
  const rateLimitOpts =
    process.env.RATE_LIMIT_MAX !== undefined
      ? {
          global: true,
          max: parseInt(process.env.RATE_LIMIT_MAX, 10),
          timeWindow: 60 * 1000,
          redis,
          keyGenerator: (request: FastifyRequest) => request.ip,
          addHeaders: {
            'x-ratelimit-limit': true,
            'x-ratelimit-remaining': true,
            'x-ratelimit-reset': true,
            'retry-after': true,
          },
        }
      : {
          global: true,
          max: 100,
          timeWindow: 60 * 1000,
          redis,
          keyGenerator: (request: FastifyRequest) => request.ip,
          addHeaders: {
            'x-ratelimit-limit': true,
            'x-ratelimit-remaining': true,
            'x-ratelimit-reset': true,
            'retry-after': true,
          },
        };
  await server.register(rateLimit, rateLimitOpts);

  await registerSwagger(server);

  // Audit logging hook
  server.addHook('onResponse', auditLogHook);

  // Core API Routes
  await server.register(adminRoutes, { prefix: '/api/v1/admin' }); // internal (Basic Auth)
  await server.register(authRoutes, { prefix: '/api/v1' });
  await server.register(testProtectedRoutes);
  await server.register(gymRoutes, { prefix: '/api/v1/gym' });
  await server.register(staffRoutes, { prefix: '/api/v1/staff' });
  await server.register(memberRoutes, { prefix: '/api/v1/members' });
  await server.register(leadRoutes, { prefix: '/api/v1/leads' });
  await server.register(paymentRoutes, { prefix: '/api/v1/payments' });
  await server.register(analyticsRoutes, { prefix: '/api/v1/analytics' });
  await server.register(notificationTemplateRoutes, { prefix: '/api/v1/notification-templates' });
  await server.register(automationRoutes, { prefix: '/api/v1/automation' });
  await server.register(whatsappRoutes, { prefix: '/api/v1/whatsapp' });
  await server.register(publicRoutes, { prefix: '/api/v1/public' });
  await server.register(publicNotifyRoutes, { prefix: '/api/v1/public' });
  await server.register(planRoutes, { prefix: '/api/v1/plans' });
  await server.register(billingRoutes, { prefix: '/api/v1/billing' });

  // Webhooks
  await server.register(whatsappWebhookRoutes, { prefix: '/webhooks' });
  await server.register(razorpayWebhookRoutes, { prefix: '/webhooks' });
  await server.register(twilioWebhookRoutes, { prefix: '/webhooks/twilio' });
  await server.register(stripeWebhookRoutes, { prefix: '/webhooks' });

  registerErrorHandler(server);
  return server;
}

// Inside start() before app.listen():
if (process.env.NODE_ENV !== 'test') {
  await app.register(async (instance) => {
    instance.addHook('onRequest', requireBasicAuth('RevMetIQ Queues'));
    await instance.register(bullBoardAdapter.registerPlugin(), {
      prefix: '/admin/queues',
    });
  });
}
```
