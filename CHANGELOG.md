# Changelog

All notable changes to this project will be documented in this file.

## [v1.0.6](https://github.com/somaz94/agentic-workflow-guard/compare/v1.0.5...v1.0.6) (2026-11-06)

### Bug Fixes

- find more shell forms of agent commands and narrow power only from their own command line ([e632996](https://github.com/somaz94/agentic-workflow-guard/commit/e632996ed28f1759773c16856f43e4030a0ed5c8))

### Documentation

- add related projects section to README ([19d1950](https://github.com/somaz94/agentic-workflow-guard/commit/19d19506d5dbe228a63010e74df2050acb39bd51))
- add a screenshot of the findings as workflow annotations ([c630565](https://github.com/somaz94/agentic-workflow-guard/commit/c6305650ae47f4d928a65114206fd9b6bf8a2e9a))

### Chores

- bump the action image to v1.0.6 ([4a9d35a](https://github.com/somaz94/agentic-workflow-guard/commit/4a9d35a1abd02613a33a2f2529240e8f9db4517c))

### Contributors

- somaz

<br/>

## [v1.0.5](https://github.com/somaz94/agentic-workflow-guard/compare/v1.0.4...v1.0.5) (2026-11-06)

### Bug Fixes

- keep the shell lexer linear and read here-documents the way bash 3.2 and 5 do ([e80d4cd](https://github.com/somaz94/agentic-workflow-guard/commit/e80d4cdba53db67d6d89d7ef9c88bf8b6599677f))

### Chores

- bump the action image to v1.0.5 ([3091bf6](https://github.com/somaz94/agentic-workflow-guard/commit/3091bf6f6ad7e740c1bb0ccae4f0c0da8f2b9436))

### Contributors

- somaz

<br/>

## [v1.0.4](https://github.com/somaz94/agentic-workflow-guard/compare/v1.0.3...v1.0.4) (2026-11-05)

### Bug Fixes

- stop a stray bracket or unclosed template from misleading the audit ([8719a52](https://github.com/somaz94/agentic-workflow-guard/commit/8719a52c1c07bf07c43723b233d4299cf3ff3e8d))

### Chores

- bump the action image to v1.0.4 ([56d6167](https://github.com/somaz94/agentic-workflow-guard/commit/56d6167294778611ebfdb67a1ee45084383e88a4))

### Contributors

- somaz

<br/>

## [v1.0.3](https://github.com/somaz94/agentic-workflow-guard/compare/v1.0.2...v1.0.3) (2026-11-05)

### Bug Fixes

- read shell comments and summary text the way their consumers do ([f3bd8c0](https://github.com/somaz94/agentic-workflow-guard/commit/f3bd8c0fa657d7a5f5ca09a7081313357cef7ff2))

### Chores

- bump the action image to v1.0.3 ([6e58404](https://github.com/somaz94/agentic-workflow-guard/commit/6e58404f882f65f2d0a1d1036ae5fdc41fed2b45))

### Contributors

- somaz

<br/>

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

