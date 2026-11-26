/**
 * Phase 0 Security Rules Specification Test Suite
 * Verifies all 12 "Dirty Dozen" payloads against firestore.rules.
 */

export interface DirtyDozenCase {
  id: number;
  name: string;
  path: string;
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  auth: { uid: string; email_verified: boolean } | null;
  payload?: Record<string, unknown>;
  expected: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_CASES: DirtyDozenCase[] = [
  {
    id: 1,
    name: 'Unauthenticated read on plan',
    path: '/plans/userA',
    operation: 'get',
    auth: null,
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Unverified email write on own plan',
    path: '/plans/userA',
    operation: 'create',
    auth: { uid: 'userA', email_verified: false },
    payload: { ownerId: 'userA' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Cross-tenant read on another user plan',
    path: '/plans/userA',
    operation: 'get',
    auth: { uid: 'userB', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'Cross-tenant list on another user history',
    path: '/plans/userA/history',
    operation: 'list',
    auth: { uid: 'userB', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'Identity spoofing via ownerId mismatch',
    path: '/plans/userA',
    operation: 'create',
    auth: { uid: 'userA', email_verified: true },
    payload: { ownerId: 'userB' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Shadow / ghost field injection on update',
    path: '/plans/userA',
    operation: 'update',
    auth: { uid: 'userA', email_verified: true },
    payload: { isAdmin: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Immutable createdAt tampering on update',
    path: '/plans/userA',
    operation: 'update',
    auth: { uid: 'userA', email_verified: true },
    payload: { createdAt: '1999-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Client-forged updatedAt timestamp',
    path: '/plans/userA',
    operation: 'update',
    auth: { uid: 'userA', email_verified: true },
    payload: { nightReadingDone: true, updatedAt: '2020-01-01T00:00:00Z' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Document ID poisoning on history',
    path: '/plans/userA/history/invalid..id..poisoning',
    operation: 'create',
    auth: { uid: 'userA', email_verified: true },
    payload: { ownerId: 'userA', date: 'invalid..id..poisoning' },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Array exhaustion exceeding 40 tasks limit',
    path: '/plans/userA',
    operation: 'update',
    auth: { uid: 'userA', email_verified: true },
    payload: { tasks: Array.from({ length: 45 }, (_, i) => ({ id: `t${i}` })) },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Value poisoning on adultPin and ntfyTopic',
    path: '/plans/userA',
    operation: 'update',
    auth: { uid: 'userA', email_verified: true },
    payload: { settings: { adultPin: 'DROP', ntfyTopic: 'http://evil' } },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Orphaned history record without parent plan',
    path: '/plans/userNoPlan/history/2026-11-25',
    operation: 'create',
    auth: { uid: 'userNoPlan', email_verified: true },
    payload: { ownerId: 'userNoPlan', date: '2026-11-25' },
    expected: 'PERMISSION_DENIED',
  },
];
