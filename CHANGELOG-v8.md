# AutoRecon v8 changelog

## 8.0.0 — Raccoon 4K

* Replaced the monolithic runtime with a Python 3.11 stage engine and process-group supervisor.
* Added atomic checkpoints, artifact reuse, restart boundaries, partial reports, explicit skip reasons and resume commands.
* Added bounded per-origin API/identity probing with isolated bodies, SCIM Users/Groups checks, optional read-only GraphQL introspection, and OIDC/Keycloak discovery.
* Added Markdown, JSON and CSV reports plus raw evidence, command and scope logs.
* Added passive/fast/balanced/deep/custom profiles and comprehensive selection/deadline controls.
