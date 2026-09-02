# AutoRecon v8 changelog

## Unreleased

* Fixed stage data flow so discovered subdomains are resolved and passed to TLS, HTTP, port, and archive collection instead of scanning only the seed host.
* Switched bulk ProjectDiscovery adapters to explicit input files, preventing `dnsx` from starting without any stdin.

## 8.0.0 — Raccoon 4K

* Replaced the monolithic runtime with a Python 3.11 stage engine and process-group supervisor.
* Added atomic checkpoints, artifact reuse, restart boundaries, partial reports, explicit skip reasons and resume commands.
* Added bounded per-origin API/identity probing with isolated bodies, SCIM Users/Groups checks, optional read-only GraphQL introspection, and OIDC/Keycloak discovery.
* Added Markdown, JSON and CSV reports plus raw evidence, command and scope logs.
* Added passive/fast/balanced/deep/custom profiles and comprehensive selection/deadline controls.
