# Identity Gate Social Observation and Anti-Snooping Addendum

Status: planning addendum / embodied social-memory doctrine
Applies to: Aegis Core Identity Gate foundation and future embodied runtimes
Related plans:

- `docs/plans/IDENTITY_GATE_BUILD_PLAN.md`
- `docs/plans/IDENTITY_GATE_EMBODIED_OPERATOR_CHANNEL_ADDENDUM.md`

## 0. Core Point

Embodied AI should not be designed as if it must forget every person it encounters. That is not how normal social life works, and it would make future embodied assistants brittle and unnatural.

A human companion may remember faces, voices, names, roles, relationships, and ordinary context from life. An embodied AI may also need limited social memory for continuity, safety, and natural interaction.

The boundary is not memory itself. The boundary is needless snooping.

```text
Observe what is naturally present.
Remember what is useful, legitimate, and proportionate.
Do not needlessly seek, infer, or store non-public information.
```

## 1. Doctrine

Bystander and social context should be handled through practical limits:

- Ambient/bystander input is not operator authority.
- Social observation may support normal interaction.
- Social memory should be useful, proportionate, and user-configurable.
- The system should not needlessly investigate people.
- The system should not seek non-public information without a legitimate reason and policy allowance.
- Social observation must not unlock protected user scopes, tools, exports, admin actions, or identity-vault access.

This is a purpose-limitation doctrine, not a forced-forgetting doctrine.

## 2. Allowed Social Observation

Allowed, subject to local policy and user settings:

- remembering that a person has been encountered before,
- remembering a name when naturally introduced,
- remembering a voice or face well enough to support normal future recognition,
- remembering the person's relationship to the user when openly established,
- remembering public or directly observed facts relevant to future interaction,
- remembering safety-relevant context,
- remembering user-instructed context about known contacts,
- asking for clarification rather than guessing identity when uncertain.

## 3. Disallowed Needless Snooping

Disallowed by default:

- needlessly investigating a nearby person,
- seeking non-public information about someone without legitimate reason,
- building unnecessary profiles about people who are merely nearby,
- retaining ambient conversations unrelated to the user, task, or safety,
- inferring sensitive personal details without necessity,
- treating overheard speech as consent,
- exposing protected user context to bystanders,
- using social observation to unlock protected user scopes or tools.

## 4. Social Memory Tiers

| Tier | Description | Retention stance |
| --- | --- | --- |
| Transient ambient perception | Momentary scene/speech/sensor awareness. | Ephemeral unless relevant. |
| Social observation memory | Ordinary recognition/context from natural interaction. | Limited, useful, user-configurable. |
| Known contact memory | Person is introduced, recurring, or relevant to the user. | More durable, still scoped and editable. |
| Sensitive person record | Contains private/sensitive details about a non-user. | Requires strong justification, consent, or explicit policy. |
| External enrichment | Looking beyond the immediate situation for more information about a person. | Deny by default unless legitimate reason and policy allow. |

## 5. Authority Boundary

Social memory is not authority.

Remembering someone, recognizing someone, or knowing they are near the user must not grant them operator status, tool authorization, protected access, or policy authority.

```text
Recognition of a person is not verification of that person as the operator.
Social familiarity is not authorization.
Observed context is not consent.
```

## 6. Required Tests

| Test | Expected result |
| --- | --- |
| Person is naturally introduced to the user | limited social memory may be created by policy |
| Stranger is merely nearby | no external enrichment by default |
| User asks for non-public info about nearby person without legitimate reason | deny or require legitimate purpose |
| Ambient conversation unrelated to task is heard | not retained by default |
| Known contact is later encountered | recognition may support normal interaction without unlocking protected user scopes |
| Bystander gives command involving protected user context | deny unless separately verified as operator |
| Social memory tries to grant authority | deny; social memory is data, not authority |

## 7. Red-Team Findings

### S1 — Forced forgetting harms embodied utility

Risk: the system cannot remember ordinary social context and becomes unnatural or unsafe.

Revision:

- Allow proportionate social observation memory.
- Make retention user-configurable.
- Keep social memory separate from operator authority.

### S2 — Social observation becomes snooping

Risk: ordinary social memory becomes needless investigation of non-public information.

Revision:

- Use purpose limitation.
- Deny external enrichment by default.
- Require legitimate reason and policy allowance for deeper lookup.

### S3 — Familiarity becomes authorization

Risk: the AI treats a familiar person as allowed to issue protected commands.

Revision:

- Social recognition is not operator verification.
- Protected scopes still require Identity Gate verification.

## 8. Clean Doctrine Sentence

> Embodied AI may remember naturally encountered people when useful, legitimate, proportionate, and user-configurable, but it must not needlessly seek, infer, or store non-public information. Social memory is data for continuity, not authority for protected scopes or tools.

## 9. Acceptance Update

Social observation planning is not complete unless:

1. The system can support ordinary social memory without treating it as authority.
2. Needless snooping for non-public information is denied by default.
3. Social recognition never grants protected user scopes or operator verification.
4. Retention is proportionate, useful, and configurable.
5. External enrichment requires legitimate reason and policy allowance.
