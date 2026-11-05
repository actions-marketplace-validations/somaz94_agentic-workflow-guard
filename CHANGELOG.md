# Changelog

All notable changes to this project will be documented in this file.

## [v1.0.2](https://github.com/somaz94/agentic-workflow-guard/compare/v1.0.1...v1.0.2) (2026-11-05)

### Bug Fixes

- stop shell comments and env scope from hiding audit findings ([876a0a4](https://github.com/somaz94/agentic-workflow-guard/commit/876a0a4ca761a55b1d5bd3e5a149459557937378))
- report audit findings a hostile workflow could hide ([4af6df0](https://github.com/somaz94/agentic-workflow-guard/commit/4af6df02f0cdc953a2a70162c56203d23f6c8e4d))

### Code Refactoring

- drop dead code and share the workflow command escaping ([813a88f](https://github.com/somaz94/agentic-workflow-guard/commit/813a88fd38e7002dc10a65e5a5663ddb6706fc90))
- route workflow and action parsing through one entry point ([5f47c44](https://github.com/somaz94/agentic-workflow-guard/commit/5f47c44e84c9936033e804f3b4c4ab5bd72a0140))

### Chores

- bump the action image to v1.0.2 ([ab1232b](https://github.com/somaz94/agentic-workflow-guard/commit/ab1232bc811b5c23fc9b1415f09da6d960eb2f1a))

### Contributors

- somaz

<br/>

## [v1.0.1](https://github.com/somaz94/agentic-workflow-guard/compare/v1.0.0...v1.0.1) (2026-11-04)

### Bug Fixes

- rename the action to Agentic Workflow Audit for the Marketplace ([8e821a1](https://github.com/somaz94/agentic-workflow-guard/commit/8e821a10ad0d568cbcde32e3057796e069697d9d))

### Chores

- bump the action image to v1.0.1 ([06657e8](https://github.com/somaz94/agentic-workflow-guard/commit/06657e8f99bdff982d662805d665bf5232707d53))

### Contributors

- somaz

<br/>

## [v1.0.0](https://github.com/somaz94/agentic-workflow-guard/releases/tag/v1.0.0) (2026-11-04)

### Features

- trace agent input through steps, local calls and command-line agents ([751be81](https://github.com/somaz94/agentic-workflow-guard/commit/751be8105e2dd30508c9f27444874cbac24abc94))
- audit workflows that run AI agents for prompt-injection exposure ([049890d](https://github.com/somaz94/agentic-workflow-guard/commit/049890da860ccef76b3b7c8015dd9507bfc7c6b0))

### Bug Fixes

- judge copied workflows, run sources and environments by what the repo shows ([af82214](https://github.com/somaz94/agentic-workflow-guard/commit/af822146d2f118d19aeb13d52934ae268760e1a4))
- stamp the release version into the binary and SARIF ([9eff064](https://github.com/somaz94/agentic-workflow-guard/commit/9eff0643cdb9a28493816051fbbe9b4928274875))
- treat open-ended interpreter arguments as running any program ([92d02e4](https://github.com/somaz94/agentic-workflow-guard/commit/92d02e4238a52e36556fe401f747f4a18a4e2249))
- bound reference tracing and close gaps from third review ([b9eb1bb](https://github.com/somaz94/agentic-workflow-guard/commit/b9eb1bba22f7edac992156cfc28b785b94e26ea2))
- close audit gaps and tighten scan limits found in review ([5a57219](https://github.com/somaz94/agentic-workflow-guard/commit/5a5721959151c841395a0b53fd5067270e663849))
- judge agent exposure by gate outputs, read-only tools and fetched input ([ccfa2a6](https://github.com/somaz94/agentic-workflow-guard/commit/ccfa2a6320d2bebf1b3dc50862f6cf2244cb90bb))

### Chores

- pin action.yml to the published v1.0.0 image ([4d62f91](https://github.com/somaz94/agentic-workflow-guard/commit/4d62f91e9d033b6eb4fa234d30e06103f19bd0b3))

### Contributors

- somaz

<br/>

