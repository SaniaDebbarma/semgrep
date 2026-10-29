```ts
// apps/api/src/routes/webhooks/razorpay.ts
import { type FastifyInstance, type FastifyPluginAsync } from 'fastify';
import { prisma, Prisma } from '@revmetiq/db';
import {
  AutomationLogType,
  AutomationChannel,
  AutomationStatus,
  AutomationTrigger,
  SubscriptionStatus,
} from '@revmetiq/db';
import { verifyWebhookSignature } from '../../services/razorpay.service.js';

interface RazorpayPaymentEntity {
  id: string;
  order_id: string | null;
  amount: number;
  currency: string;
  status: string;
  method: string;
  email: string | null;
  contact: string | null;
  error_code: string | null;
  error_description: string | null;
  notes: Record<string, string | undefined>;
}

interface RazorpaySubscriptionEntity {
  id: string;
  plan_id: string;
  customer_id: string | null;
  status: string;
  current_start: number | null;
  current_end: number | null;
  charge_at: number | null;
  start_at: number | null;
  end_at: number | null;
  ended_at: number | null;
  notes: Record<string, string | undefined>;
}

type WebhookEvent =
  | { event: 'payment.captured'; payload: { payment: { entity: RazorpayPaymentEntity } } }
  | { event: 'payment.failed'; payload: { payment: { entity: RazorpayPaymentEntity } } }
  | { event: 'subscription.activated'; payload: { subscription: { entity: RazorpaySubscriptionEntity } } }
  | { event: 'subscription.halted'; payload: { subscription: { entity: RazorpaySubscriptionEntity } } }
  | { event: 'subscription.cancelled'; payload: { subscription: { entity: RazorpaySubscriptionEntity } } }
  | { event: 'subscription.charged'; payload: { subscription: { entity: RazorpaySubscriptionEntity } } }
  | { event: 'subscription.completed'; payload: { subscription: { entity: RazorpaySubscriptionEntity } } }
  | { event: 'subscription.resumed'; payload: { subscription: { entity: RazorpaySubscriptionEntity } } };

type Tx = Prisma.TransactionClient;

async function loadGymForSubscriptionEvent(
  tx: Tx,
  entity: RazorpaySubscriptionEntity
) {
  const gymId = entity.notes?.gymId;
  if (!gymId) return null;

  const gym = await tx.gym.findUnique({
    where: { id: gymId },
    select: { id: true, email: true, name: true, ownerName: true, planTier: true },
  });
  return gym ?? null;
}

async function processSubscriptionActivated(
  tx: Tx,
  entity: RazorpaySubscriptionEntity
): Promise<void> {
  const gym = await loadGymForSubscriptionEvent(tx, entity);
  if (!gym) return;

  await tx.gym.update({
    where: { id: gym.id },
    data: {
      subscriptionStatus: SubscriptionStatus.active,
      razorpaySubscriptionId: entity.id,
      isActive: true,
    },
  });

  await tx.automationLog.create({
    data: {
      gymId: gym.id,
      type: AutomationLogType.subscription_activated,
      channel: AutomationChannel.internal,
      status: AutomationStatus.sent,
      triggeredBy: AutomationTrigger.event,
      externalMessageId: entity.id,
      metadata: {
        razorpaySubscriptionId: entity.id,
        planId: entity.plan_id,
        currentStart: entity.current_start,
        currentEnd: entity.current_end,
        chargeAt: entity.charge_at,
      },
    },
  });
}

// Scoped plugin: captures raw Buffer before JSON parsing for HMAC verification
const razorpayWebhookRoutes: FastifyPluginAsync = async (
  fastify: FastifyInstance
): Promise<void> => {
  fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (request, body, done) => {
    request.rawBody = body as Buffer;
    try {
      const parsed: unknown = JSON.parse((body as Buffer).toString('utf-8'));
      done(null, parsed);
    } catch (err) {
      done(err instanceof Error ? err : new Error('Invalid JSON in webhook body'), undefined);
    }
  });

  fastify.post('/razorpay', async (request, reply): Promise<void> => {
    const signature = request.headers['x-razorpay-signature'];

    if (typeof signature !== 'string' || signature.length === 0) {
      return reply.code(400).send({ error: 'Missing signature header' });
    }

    const rawBody = request.rawBody;
    if (!rawBody || rawBody.length === 0) {
      return reply.code(400).send({ error: 'Empty request body' });
    }

    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    if (!webhookSecret || !verifyWebhookSignature(rawBody, signature, webhookSecret)) {
      return reply.code(400).send({ error: 'Invalid signature' });
    }

    // Dedupe key: required to prevent replay / duplicate processing under at-least-once delivery
    const eventId = request.headers['x-razorpay-event-id'];
    if (typeof eventId !== 'string' || eventId.length === 0) {
      return reply.code(400).send({ error: 'Missing event id header' });
    }

    const body = request.body as WebhookEvent;

    try {
      await prisma.$transaction(async (tx) => {
        // Claim FIRST via unique index on (provider, eventId).
        // Redelivery throws P2002 before any side effects execute.
        await tx.webhookEvent.create({
          data: { provider: 'razorpay', eventId, eventType: body.event },
        });
        await dispatchEvent(tx, body);
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        request.log.info(
          { eventId, event: body.event },
          '[razorpay/webhook] Duplicate delivery acknowledged, not reprocessed'
        );
        return reply.code(200).send({ received: true });
      }
      request.log.error(
        { err, eventId, event: body.event },
        '[razorpay/webhook] Processing failed'
      );
      return reply.code(500).send({ error: 'Webhook processing failed' });
    }

    return reply.code(200).send({ received: true });
  });
};

async function dispatchEvent(tx: Tx, body: WebhookEvent): Promise<void> {
  switch (body.event) {
    case 'subscription.activated':
    case 'subscription.resumed':
      return processSubscriptionActivated(tx, body.payload.subscription.entity);
    // ... other event handlers (payment.captured, payment.failed, halted, cancelled)
    default:
      return;
  }
}

export default razorpayWebhookRoutes;
```
