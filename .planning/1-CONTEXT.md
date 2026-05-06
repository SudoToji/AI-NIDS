# Phase 1 Context: Foundation & Testing

**Phase:** 1
**Created:** 2026-05-07

## Decisions Made

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scope | All 5 criteria | User wants comprehensive foundation |
| Coverage Target | 80% for core modules | Standard threshold |
| Documentation | Docstrings + README | Both needed for maintainability |
| Type Hints | Progressive addition | Not blocking, add where practical |
| Linting | Ruff with defaults | Industry standard |
| Integration Tests | Detection pipeline E2E | Core value must work |

## Core Modules (Priority for Coverage)

| Module | Location | Priority |
|-------|----------|----------|
| HybridPredictor | `src/models/hybrid_predictor.py` | High |
| DeepVerifier | `src/models/deep_verifier.py` | High |
| UNSWProcessor | `src/features/unsw_processor.py` | High |
| AlertManager | `src/detector/alert_manager.py` | Medium |
| EnsembleVoting | `src/models/ensemble_voting.py` | Medium |

## Documentation Requirements

1. **Docstrings** — All public functions/classes
2. **README updates** — Update root README with current architecture
3. **API docs** — Already exists in `docs/API.md`, verify accuracy

## Type Hints Strategy

- Add types where obvious (function signatures, return types)
- Don't block on complex generics
- Use `Any` where appropriate

## Linting Rules

- Use Ruff defaults
- Fix violations incrementally
- Add `# noqa` only where necessary with comment

## Integration Test Scope

- Test: capture → features → detection → alert pipeline
- Mock external APIs (OpenRouter)
- Use synthetic data for testing

## Success Criteria Mapping

| Criterion | Implementation |
|-----------|---------------|
| Test Coverage | pytest-cov, target core modules 80%+ |
| Documentation | docstrings + README updates |
| Type Hints | Add where practical |
| Linting | ruff check passes |
| Integration Tests | E2E pipeline test |

---

*Last updated: 2026-05-07 after discuss-phase 1*