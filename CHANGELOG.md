# Changelog

## [1.0.1](https://github.com/jr200-labs/keymint/compare/v1.0.0...v1.0.1) (2026-04-25)


### Bug Fixes

* **ci:** top-level permissions + correct secret name (build + renovate) ([#19](https://github.com/jr200-labs/keymint/issues/19)) ([cb5b1d9](https://github.com/jr200-labs/keymint/commit/cb5b1d96e6f4c9fa56c2eacbc2c908e82471efc6))

## 1.0.0 (2026-04-25)


### Features

* **config:** add config + sops packages and config-driven mint cli ([93a3d26](https://github.com/jr200-labs/keymint/commit/93a3d26ac6a1560763af629ce4bdd02b89961664))
* **config:** add config + sops packages and config-driven mint cli ([91855fe](https://github.com/jr200-labs/keymint/commit/91855fe1cd72d5cabfe948673ba4a851a0c60a95))
* **credhelper:** implement git credential helper protocol ([#5](https://github.com/jr200-labs/keymint/issues/5)) ([ba48a97](https://github.com/jr200-labs/keymint/commit/ba48a97497fb0e2f203acab38afd64c47ae55bce))
* **mint:** add jwt signing and installation token exchange ([aeba4c2](https://github.com/jr200-labs/keymint/commit/aeba4c2c0c8841d9083fe5722e5e4d3424f54a34))
* **mint:** JWT signing + installation token exchange ([ce7e59a](https://github.com/jr200-labs/keymint/commit/ce7e59aa57e1dc5a9f3b4653350cdc8f61acef59))
* negative tokenreview cache, split livez/readyz, debounced reload ([#14](https://github.com/jr200-labs/keymint/issues/14)) ([c111b74](https://github.com/jr200-labs/keymint/commit/c111b74bdc74e302aee086fe438eaf89b59f035e))
* **observability:** prometheus metrics + opentelemetry tracing ([#8](https://github.com/jr200-labs/keymint/issues/8)) ([272bc5a](https://github.com/jr200-labs/keymint/commit/272bc5a7970756555868320214c2caf52ca7578d))
* operational hardening + project-data scrub ([#7](https://github.com/jr200-labs/keymint/issues/7)) ([f3dd78b](https://github.com/jr200-labs/keymint/commit/f3dd78beac97c533fb7b930516f80ce5bf29dfce))
* scaffold repository skeleton ([82e28ff](https://github.com/jr200-labs/keymint/commit/82e28ff8ef825047c472251d09c850dce217ce98))
* scaffold repository skeleton ([481906f](https://github.com/jr200-labs/keymint/commit/481906f152f55d14f3f8ad86b6d7f20d76bf7200))
* **server:** http service mode with kubernetes tokenreview ([#6](https://github.com/jr200-labs/keymint/issues/6)) ([2494d89](https://github.com/jr200-labs/keymint/commit/2494d8957d68ca62ef6eabf51b6aae2a048d008a))
* token audit fingerprint + ed25519 private key support ([#17](https://github.com/jr200-labs/keymint/issues/17)) ([97073f6](https://github.com/jr200-labs/keymint/commit/97073f6d58705165823f336928e45a1147a7fa04))
* tokenreview cache + hot config reload + github breaker/observability ([#12](https://github.com/jr200-labs/keymint/issues/12)) ([be54cde](https://github.com/jr200-labs/keymint/commit/be54cde65c4a947c8231bc1fd0cd67251e51eb6d))


### Bug Fixes

* address five critical security and availability flaws ([#9](https://github.com/jr200-labs/keymint/issues/9)) ([b07b065](https://github.com/jr200-labs/keymint/commit/b07b0657536e11b36d10af528113fdcee7c5dd53))
* address ten resilience and performance flaws ([#10](https://github.com/jr200-labs/keymint/issues/10)) ([a09d9b9](https://github.com/jr200-labs/keymint/commit/a09d9b92baa729f06157993b0c6d1ea91faa5ccd))
* breaker / cardinality / singleflight context bugs ([#11](https://github.com/jr200-labs/keymint/issues/11)) ([c3a342b](https://github.com/jr200-labs/keymint/commit/c3a342b2a9159e7c845f8a86fbfa36b98d678a22))
* limiter init race / pem-rotation token leak / refresh stampede ([#15](https://github.com/jr200-labs/keymint/issues/15)) ([fd1eab7](https://github.com/jr200-labs/keymint/commit/fd1eab726227758194e1ebcba500bc7a2d385c72))
* per-endpoint isolation, lock-free limiter, bounded caches, RFC bearer ([#18](https://github.com/jr200-labs/keymint/issues/18)) ([3905502](https://github.com/jr200-labs/keymint/commit/39055026d81978174ecd7d20b72fc96980d5bd5c))
* proxy-aware client ip / stale-but-valid token / k8s-safe watcher ([#13](https://github.com/jr200-labs/keymint/issues/13)) ([ed8b9d0](https://github.com/jr200-labs/keymint/commit/ed8b9d040c0d4eeea756e046bd697f5d3e6ba812))
* tri-state tokenreview / non-evicting limiter / fsnotify pem gen ([#16](https://github.com/jr200-labs/keymint/issues/16)) ([93f3336](https://github.com/jr200-labs/keymint/commit/93f33366a2b869661d9ed52b854f10d2ebde87f8))
* use cmd.Println to satisfy errcheck linter ([a1105d2](https://github.com/jr200-labs/keymint/commit/a1105d267966ec4cdd8d41fafd7332127a274aaf))
