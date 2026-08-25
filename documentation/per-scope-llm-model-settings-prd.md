# Per-Scope LLM Model Settings PRD

## Summary

BiocBot currently stores API credentials and the active AI provider on each AI-enabled scope, but stores chat, reasoning, backend, and embedding model choices globally per provider. This makes an administrator's model change affect every course or shared surface using that provider.

Model configuration must instead belong to the individual scope and provider. A course, Super Course bucket, instructor-notes surface, or global instructor Super Course chat may use the same literal API key as another scope while retaining completely independent model settings.

## Goals

- Store a complete model configuration for every provider on every AI-enabled scope.
- Keep model configuration editable only by system administrators.
- Keep provider and API-key selection available to the instructors who can manage that scope today.
- Derive the selectable model roster from the specific scope's saved key, filtered to models BiocBot supports.
- Use copy-on-create default templates so normal onboarding remains immediately usable without creating a live global dependency.
- Limit embedding-model changes and re-indexing to the affected scope.
- Preserve the behavior of existing scopes during migration.

## Non-goals

- Sharing model configuration merely because two scopes contain the same API key.
- Giving instructors access to model selection.
- Changing the membership or retrieval semantics of Super Course features.
- Deleting old Qdrant collections during a model change or rollback.

## AI-enabled scopes

The feature applies to:

1. Individual courses.
2. Student-facing Super Course buckets.
3. Instructor notes.
4. Global instructor Super Course chat.

Each scope stores provider-specific configurations so switching away from and back to a provider restores that scope's previous configuration.

## Configuration fields

Each scope/provider configuration contains:

- Front-end chat model.
- Front-end reasoning effort.
- Whether backend processing inherits the front-end settings.
- Optional backend chat-model override.
- Backend reasoning effort.
- Embedding model and embedding revision.
- Embedding vector size when discovered dynamically.
- Models discovered through that scope's credential.
- Configuration status and audit timestamps/actor.
- A staged embedding configuration and migration identifier when re-indexing is in progress.

## Defaults

System-wide provider settings become **defaults for newly created AI configurations**. They are templates, not runtime settings.

- Existing global settings seed the default templates during migration.
- When a new scope/provider credential is saved, BiocBot copies the applicable template into the scope.
- Changing a template affects only provider configurations created afterward.
- Existing scopes never read live model choices from the template after their configuration has been materialized.
- OpenAI and Sandbox may use deployment-provided bootstrap defaults.
- Proxy has no implicit model guess. A Proxy configuration without a compatible explicit template requires system-admin configuration.

## Onboarding flow

1. An instructor chooses an AI provider and enters a required key.
2. BiocBot validates the key and discovers the models available to it.
3. BiocBot intersects that roster with models/operations supported by the application.
4. BiocBot copies the provider's new-scope default template into the course.
5. If the key supports the complete copied configuration, the course is marked ready and onboarding continues normally.
6. If the key is valid but the copied configuration is missing or incompatible, BiocBot still creates the course and stores the encrypted key, but marks AI as needing admin configuration.
7. While configuration is required, AI-dependent actions are blocked with a clear status; non-AI course setup remains available.
8. A system administrator selects compatible front-end, backend, reasoning, and embedding settings from that course key's roster. Saving a complete configuration makes AI available.

The submitted API key and onboarding request body must never be written to browser or server logs.

## Replacement-key flow

- A valid replacement key is accepted and becomes the stored key for that scope/provider.
- If the existing configuration is compatible with the new key, AI remains ready.
- If it is incompatible, AI for that scope is blocked until a system administrator selects a compatible configuration.
- No arbitrary fallback model is selected automatically.
- Other scopes using the same literal key are unaffected.

## Admin experience

- Course settings show model controls for the currently selected course.
- The active provider is shown first; other providers with saved keys remain available as tabs or sections.
- Bucket model controls live beside the selected bucket's key controls.
- Notes model controls live beside the notes key controls.
- Global instructor Super Course model controls live beside its key controls.
- Model controls are not rendered or returned to non-system-admin users.
- A clear **Needs admin configuration** state identifies valid credentials whose models have not been configured.
- The defaults screen is labelled as applying only to future AI configurations.

## Model availability and validation

- OpenAI selectors contain only BiocBot-supported models accessible to the scope's key.
- Sandbox selectors contain only supported models accessible to the scope's key.
- Proxy selectors use only the exact roster returned for that scope's key.
- Proxy chat and embedding choices continue to be validated by performing the relevant operation because its roster does not expose capabilities.
- A configuration cannot be saved if any selected model is unavailable or incompatible with its intended operation.

## Embedding behavior

- A course embedding change re-indexes only that course's course-chat profile.
- A course embedding change does not modify or rebuild a Super Course bucket, notes, or global instructor Super Course profile.
- A bucket embedding change rebuilds only the content required for that bucket's retrieval profile.
- A notes embedding change rebuilds notes only.
- A global instructor Super Course embedding change rebuilds only its own retrieval pool.
- The current embedding profile remains active until its scoped migration completes successfully.
- Old vectors are retained unless a staged migration is explicitly cancelled and its partial output is cleaned up.
- Concurrent embedding migrations are restricted per scope/provider, not globally per provider.

## Existing-data migration

- Copy every existing global provider configuration into every existing AI-enabled scope, including providers without a stored key.
- Copy pending state only when it can be safely mapped to an individual scope; otherwise finish or cancel global migrations before rollout.
- Preserve each scope's active provider and all encrypted credentials.
- After materialization, runtime resolution reads only the scope's provider configuration.
- Environment/bootstrap values remain a fallback for creating default templates, not for silently changing an existing scope.

## Authorization

- Only system administrators may read model rosters/configuration details or change model settings.
- Existing instructor permissions for entering, testing, and switching provider keys remain unchanged.
- API endpoints must resolve and authorize the target scope before returning or modifying configuration.

## Acceptance criteria

- Changing Course A from one supported chat model/reasoning level to another does not change Course B, even when both use the same key.
- Changing any provider configuration on a course does not change any bucket, notes, or global instructor Super Course configuration.
- A newly created course receives a snapshot of the current new-scope defaults.
- Later default changes do not affect that course.
- A valid but incompatible onboarding key creates the course in a visible needs-admin-configuration state and blocks only AI-dependent operations.
- A compatible onboarding key creates an immediately usable course.
- Every model selector is derived from that scope's credential rather than a union accumulated from other credentials.
- Embedding impact, migration, activation, and rollback operate on one scope/provider.
- Existing courses behave identically immediately after migration.
- Non-system-admin clients cannot read or edit model settings.
- Onboarding no longer logs API keys or request payloads containing them.

