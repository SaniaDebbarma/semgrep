```ts
// packages/shared/src/validators/member.ts
import { z } from 'zod';
import { PaymentModeEnum } from './payment.js';

const GenderEnum = z.enum(['male', 'female', 'other', 'prefer_not_to_say']);

const MemberSourceEnum = z.enum([
  'walk_in',
  'referral',
  'social_media',
  'google',
  'campaign',
  'other',
]);

const MemberStatusEnum = z.enum([
  'active',
  'expiring_soon',
  'expired',
  'paused',
  'cancelled',
  'pending_payment',
]);

const SortByEnum = z.enum(['name', 'expiryDate', 'startDate', 'createdAt', 'status']);
const SortOrderEnum = z.enum(['asc', 'desc']);

export const createMemberSchema = z.object({
  name: z.string({ required_error: 'Name is required' }).min(1, 'Name is required').max(100),
  phone: z
    .string({ required_error: 'Phone is required' })
    .min(7, 'Phone must be at least 7 characters')
    .max(20, 'Phone must be at most 20 characters'),
  email: z.string().email('Invalid email format').optional(),
  dateOfBirth: z.coerce.date().optional(),
  gender: GenderEnum.optional(),
  planId: z.string().uuid('planId must be a valid UUID').optional(),
  planType: z
    .string({ required_error: 'planType is required' })
    .min(1, 'planType is required')
    .max(100),
  planAmountPaisa: z
    .number({ required_error: 'planAmountPaisa is required' })
    .int('planAmountPaisa must be an integer')
    .nonnegative('planAmountPaisa must be >= 0'),
  startDate: z.coerce.date({ required_error: 'startDate is required' }),
  expiryDate: z.coerce.date({ required_error: 'expiryDate is required' }),
  notes: z.string().max(2000, 'Notes must be at most 2000 characters').optional(),
  trainerId: z.string().uuid('trainerId must be a valid UUID').optional(),
  source: MemberSourceEnum.optional(),
  // Affirmative WhatsApp opt-in consent captured at signup (never defaulted to true)
  whatsappOptIn: z.boolean().optional(),
});

export const updateMemberSchema = createMemberSchema.partial();

// Renew contract: startDate/expiryDate are derived server-side from GymPlan.durationDays
// and never trusted from the client payload.
export const renewMemberSchema = z.object({
  planId: z.string({ required_error: 'planId is required' }).uuid('planId must be a valid UUID'),
  amountPaisa: z
    .number({ required_error: 'amountPaisa is required' })
    .int('amountPaisa must be an integer (paisa)')
    .min(1, 'amountPaisa must be at least 1 paisa'),
  paymentMode: PaymentModeEnum,
  paymentDate: z.coerce.date().optional(),
});

export const listMembersQuerySchema = z.object({
  search: z.string().max(100).optional(),
  status: MemberStatusEnum.optional(),
  planId: z.string().uuid().optional(),
  expiringInDays: z.coerce
    .number()
    .int()
    .positive()
    .max(365, 'expiringInDays must be <= 365')
    .optional(),
  sortBy: SortByEnum.optional().default('createdAt'),
  sortOrder: SortOrderEnum.optional().default('desc'),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100, 'limit must be <= 100').default(10),
});

export const memberIdParamSchema = z.object({
  id: z.string().uuid('Member ID must be a valid UUID'),
});

export type CreateMemberInput = z.infer<typeof createMemberSchema>;
export type UpdateMemberInput = z.infer<typeof updateMemberSchema>;
export type ListMembersQuery = z.infer<typeof listMembersQuerySchema>;
export type MemberIdParam = z.infer<typeof memberIdParamSchema>;
```
