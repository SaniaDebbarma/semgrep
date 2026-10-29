```ts
// apps/api/src/routes/members.ts
import { FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import { StaffRole, prisma } from '@revmetiq/db';
import {
  createMemberSchema,
  updateMemberSchema,
  renewMemberSchema,
  listMembersQuerySchema,
  memberIdParamSchema,
  checkInSchema,
} from '@revmetiq/shared';
import { authenticate } from '../middlewares/authenticate.js';
import { requireRole } from '../middlewares/requireRole.js';
import { deriveRenewalExpiry, getISTDayBoundaries } from '../automation/utils/dateUtils.js';
import { recordPaymentInTx } from '../services/paymentService.js';
import {
  listMembers,
  getMemberById,
  createMember,
  updateMember,
  softDeleteMember,
  bulkImportMembers,
} from '../services/memberService.js';
import { recordVisit } from '../services/visitService.js';
import { verifyStaffPin } from '../services/staffService.js';

const READ_ROLES = [StaffRole.owner, StaffRole.manager, StaffRole.receptionist, StaffRole.trainer];
const WRITE_ROLES = [StaffRole.owner, StaffRole.manager, StaffRole.receptionist];
const CHECKIN_ROLES = [
  StaffRole.owner,
  StaffRole.manager,
  StaffRole.receptionist,
  StaffRole.trainer,
  StaffRole.front_desk,
];

const MAX_CSV_ROWS = 500;
const MAX_CSV_FILE_BYTES = 5 * 1024 * 1024; // 5 MiB
const ALLOWED_CSV_MIMES = new Set([
  'text/csv',
  'text/plain',
  'application/csv',
  'application/vnd.ms-excel',
]);

// Dual-credential preHandler for POST /checkin:
// Accepts either a staff JWT session OR an unattended kiosk staff PIN (verified in handler).
async function checkInAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const body = request.body as { kiosk?: unknown } | undefined;
  if (body && typeof body === 'object' && body.kiosk !== undefined) return;

  await authenticate(request, reply);
  if (!request.gym) return;
  await requireRole(CHECKIN_ROLES)(request, reply);
}

export async function memberRoutes(server: FastifyInstance): Promise<void> {
  // 1. GET / — List members (Tenant-scoped + Query Zod validation)
  server.get(
    '/',
    { preHandler: [authenticate, requireRole(READ_ROLES)] },
    async (request, reply) => {
      const parsed = listMembersQuerySchema.safeParse(request.query);
      if (!parsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: parsed.error.flatten().fieldErrors });
      }
      try {
        const result = await listMembers(request.gym!.gymId, parsed.data);
        return reply.send(result);
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );

  // 2. POST / — Create member (Tenant-scoped + Body Zod validation)
  server.post(
    '/',
    { preHandler: [authenticate, requireRole(WRITE_ROLES)] },
    async (request, reply) => {
      const parsed = createMemberSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: parsed.error.flatten().fieldErrors });
      }
      try {
        const member = await createMember(request.gym!.gymId, parsed.data);
        return reply.code(201).send({ ok: true, data: member });
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );

  // 3. POST /checkin — Session or Kiosk PIN auth + path-enforced entryMethod
  server.post(
    '/checkin',
    {
      schema: {
        body: {
          type: 'object',
          required: ['code'],
          properties: {
            code: { type: 'string' },
            entryMethod: {
              type: 'string',
              enum: ['staff_scan', 'staff_manual', 'turnstile', 'kiosk'],
            },
            kiosk: {
              type: 'object',
              required: ['gymId', 'staffId', 'pin'],
              properties: {
                gymId: { type: 'string', format: 'uuid' },
                staffId: { type: 'string', format: 'uuid' },
                pin: { type: 'string' },
              },
            },
          },
        },
      },
      preHandler: [checkInAuth],
    },
    async (request, reply) => {
      const parsed = checkInSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: parsed.error.flatten().fieldErrors });
      }

      const kiosk = parsed.data.kiosk;
      if (kiosk && parsed.data.entryMethod && parsed.data.entryMethod !== 'kiosk') {
        return reply
          .code(400)
          .send({ error: "A PIN-authorised check-in is always recorded as 'kiosk'" });
      }
      if (!kiosk && parsed.data.entryMethod === 'kiosk') {
        return reply.code(400).send({ error: "entryMethod 'kiosk' requires a staff PIN" });
      }

      try {
        if (kiosk) await verifyStaffPin(kiosk.gymId, kiosk.staffId, kiosk.pin);

        const entryMethod = kiosk ? 'kiosk' : (parsed.data.entryMethod ?? 'staff_scan');
        const result = await recordVisit({
          gymId: kiosk ? kiosk.gymId : request.gym!.gymId,
          code: parsed.data.code,
          entryMethod,
          recordedByStaffId:
            entryMethod === 'turnstile'
              ? null
              : kiosk
                ? kiosk.staffId
                : (request.gym!.staffId ?? null),
        });

        return reply.code(result.deduplicated ? 200 : 201).send({ ok: true, data: result });
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );

  // 4. POST /bulk-import — Stream CSV upload with MIME, byte-size, and 500-row cap
  server.post(
    '/bulk-import',
    { preHandler: [authenticate, requireRole(WRITE_ROLES)] },
    async (request, reply) => {
      let file: Awaited<ReturnType<typeof request.file>>;
      try {
        file = await request.file({ limits: { fileSize: MAX_CSV_FILE_BYTES } });
      } catch (err: unknown) {
        const e = err as Error & { code?: string };
        if (e.code === 'FST_FILES_LIMIT' || e.code === 'FST_REQ_FILE_TOO_LARGE') {
          return reply.code(413).send({
            error: `File too large. Maximum upload size is ${MAX_CSV_FILE_BYTES / 1024 / 1024} MiB.`,
          });
        }
        throw err;
      }

      if (!file) return reply.code(400).send({ error: 'No file provided.' });

      if (!ALLOWED_CSV_MIMES.has(file.mimetype)) {
        file.file.resume();
        return reply
          .code(415)
          .send({ error: 'Unsupported file type. Only CSV files are accepted.' });
      }

      let parseResult: StreamParseResult;
      try {
        // streamParseCsv validates each row via createMemberSchema.safeParse(mapped)
        // and aborts parser if rowIndex > MAX_CSV_ROWS (500)
        parseResult = await streamParseCsv(file.file);
      } catch (err: unknown) {
        return reply.code(422).send({ error: `Failed to parse CSV: ${(err as Error).message}` });
      }

      if (parseResult.abortedDueToLimit) {
        return reply
          .code(400)
          .send({ error: 'Maximum 500 members per import. Split into multiple files.' });
      }

      try {
        const result = await bulkImportMembers(
          request.gym!.gymId,
          parseResult.validRows,
          parseResult.errors,
          parseResult.total
        );
        return reply.code(result.errors.length > 0 ? 207 : 201).send(result);
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );

  // 5. GET /:id & PATCH /:id — Param + Body Zod validation & Tenant Scoping
  server.get(
    '/:id',
    { preHandler: [authenticate, requireRole(READ_ROLES)] },
    async (request, reply) => {
      const paramParsed = memberIdParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: paramParsed.error.flatten().fieldErrors });
      }
      try {
        const member = await getMemberById(request.gym!.gymId, paramParsed.data.id);
        return reply.send({ ok: true, data: member });
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );

  server.patch(
    '/:id',
    { preHandler: [authenticate, requireRole(WRITE_ROLES)] },
    async (request, reply) => {
      const paramParsed = memberIdParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: paramParsed.error.flatten().fieldErrors });
      }
      const bodyParsed = updateMemberSchema.safeParse(request.body);
      if (!bodyParsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: bodyParsed.error.flatten().fieldErrors });
      }
      try {
        const updated = await updateMember(
          request.gym!.gymId,
          paramParsed.data.id,
          bodyParsed.data,
          request.gym!.staffId
        );
        return reply
          .code(200)
          .send({ ok: true, data: updated, message: 'Member updated successfully' });
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );

  // 6. POST /:id/renew — Direct Prisma Tenant Scoping & Atomic Transaction
  server.post(
    '/:id/renew',
    {
      schema: {
        params: {
          type: 'object',
          properties: { id: { type: 'string', format: 'uuid' } },
          required: ['id'],
        },
      },
      preHandler: [authenticate, requireRole(WRITE_ROLES)],
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const bodyParsed = renewMemberSchema.safeParse(request.body);
      if (!bodyParsed.success) {
        return reply.code(400).send({
          ok: false,
          error: 'Validation failed',
          details: bodyParsed.error.flatten().fieldErrors,
        });
      }
      const { planId, amountPaisa, paymentMode, paymentDate } = bodyParsed.data;
      const gymId = request.gym!.gymId;
      const staffId = request.gym!.staffId;

      try {
        // Confirm planId belongs to THIS gym (prevents cross-tenant plan IDOR)
        const plan = await prisma.gymPlan.findFirst({
          where: { id: planId, gymId },
          select: { id: true, durationDays: true, amountPaisa: true },
        });
        if (!plan) {
          return reply.code(400).send({ ok: false, error: 'Invalid plan for this gym' });
        }

        const chargePaisa = plan.amountPaisa;

        // Read member strictly scoped by gymId
        const current = await prisma.member.findFirst({
          where: { id, gymId, deletedAt: null },
          select: { expiryDate: true },
        });
        if (!current) {
          return reply.code(404).send({ ok: false, error: 'Member not found' });
        }

        const gym = await prisma.gym.findUnique({
          where: { id: gymId },
          select: {
            id: true,
            slug: true,
            name: true,
            gstin: true,
            countryCode: true,
            taxInclusive: true,
            logoUrl: true,
            address: true,
          },
        });
        if (!gym) {
          return reply.code(404).send({ ok: false, error: 'Gym not found' });
        }

        const startDate = getISTDayBoundaries(0).start;
        const expiryDate = deriveRenewalExpiry(current.expiryDate, plan.durationDays);

        const payment = await prisma.$transaction(
          async (tx) => {
            // updateMany enforces gymId in WHERE clause inside the transaction
            await tx.member.updateMany({
              where: { id, gymId, deletedAt: null },
              data: {
                planId,
                planAmountPaisa: chargePaisa,
                startDate,
                expiryDate,
                status: 'active',
                outstandingDuePaisa: { increment: chargePaisa },
              },
            });

            return recordPaymentInTx(
              tx,
              gymId,
              {
                memberId: id,
                amountPaisa,
                paymentMode,
                paymentDate: paymentDate ?? new Date(),
              },
              staffId,
              gym
            );
          },
          { timeout: 15000, maxWait: 10000 }
        );

        return reply.code(200).send({
          ok: true,
          data: payment.member,
          payment: payment.payment,
          message: 'Member renewed successfully',
        });
      } catch (error) {
        server.log.error(error);
        return reply.code(500).send({ ok: false, error: 'Failed to renew member' });
      }
    }
  );

  // 7. DELETE /:id — Soft-delete scoped by gymId
  server.delete(
    '/:id',
    { preHandler: [authenticate, requireRole(WRITE_ROLES)] },
    async (request, reply) => {
      const paramParsed = memberIdParamSchema.safeParse(request.params);
      if (!paramParsed.success) {
        return reply
          .code(400)
          .send({ error: 'Validation Error', details: paramParsed.error.flatten().fieldErrors });
      }
      try {
        await softDeleteMember(request.gym!.gymId, paramParsed.data.id);
        return reply.code(204).send();
      } catch (err: unknown) {
        const e = err as Error & { statusCode?: number };
        return reply.code(e.statusCode ?? 500).send({ error: e.message });
      }
    }
  );
}
```
