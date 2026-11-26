# Security Specification — Plan de Acción · Modo Piloto

## 1. Data Invariants
1. **Strict Ownership & Verified Email**: A user can only read or write `/plans/{userId}` and `/plans/{userId}/history/{dateKey}` if `request.auth != null`, `request.auth.token.email_verified == true`, and `request.auth.uid == userId`.
2. **Master Gate on History**: Every single-document operation on `/plans/{userId}/history/{dateKey}` verifies that the parent `/plans/{userId}` document exists and its `ownerId == request.auth.uid`.
3. **Immutable Identity & Creation Timestamps**: `ownerId` and `createdAt` can never be modified after creation. `createdAt == request.time` on create; `updatedAt == request.time` on create and update.
4. **Bounded Collections & Types**: `tasks` is strictly capped at 40 items, `minuteUndoStack` at 50 items, all string fields enforce explicit `.size()` bounds, `adultPin` matches `^[0-9]{4}$`, and `ntfyTopic` matches `^$|^[a-zA-Z0-9_\-]{6,64}$`.
5. **No Blanket List / No Ghost Fields**: `/plans` denies `list` completely. `/plans/{userId}/history` enforces `resource.data.ownerId == request.auth.uid` on `list` without `get()`. All writes enforce `hasAll` + `hasOnly` and action-specific `affectedKeys().hasOnly(...)`.

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Unauthenticated Read/Write**: Read or write `/plans/userA` with `auth == null` → `PERMISSION_DENIED`.
2. **Unverified Email Spoof**: Write `/plans/userA` with `uid: "userA"` but `email_verified: false` → `PERMISSION_DENIED`.
3. **Cross-Tenant Read**: `userB` attempts `get` on `/plans/userA` → `PERMISSION_DENIED`.
4. **Cross-Tenant History List**: `userB` attempts `list` on `/plans/userA/history` → `PERMISSION_DENIED`.
5. **Identity Spoofing on Create**: `userA` creates `/plans/userA` with `ownerId: "userB"` → `PERMISSION_DENIED`.
6. **Shadow / Ghost Field Injection**: `userA` updates `/plans/userA` adding `isAdmin: true` → `PERMISSION_DENIED`.
7. **Immutable Field Tampering**: `userA` updates `/plans/userA` modifying `createdAt` or `ownerId` → `PERMISSION_DENIED`.
8. **Client-Forged Timestamp**: `userA` writes `updatedAt` with a client timestamp != `request.time` → `PERMISSION_DENIED`.
9. **ID Poisoning**: `userA` writes `/plans/userA/history/invalid..id..1500chars` → `PERMISSION_DENIED`.
10. **Array Exhaustion (Denial of Wallet)**: `userA` writes 45 tasks into `tasks` array (> 40 limit) → `PERMISSION_DENIED`.
11. **Value Poisoning on Settings**: `userA` sets `settings.adultPin = "DROP TABLE"` or `ntfyTopic = "http://evil"` → `PERMISSION_DENIED`.
12. **Orphaned History Record**: `userA` creates `/plans/userA/history/2026-11-25` when parent `/plans/userA` does not exist → `PERMISSION_DENIED`.
