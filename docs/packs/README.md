# Pack Index

This index lists pack IDs you can enable under `[packs]` in `~/.config/dcg/config.toml`.

## Core (always enabled)
- `core.git`
- `core.filesystem`

## Storage
- `storage.s3`
- `storage.gcs`
- `storage.minio`
- `storage.azure_blob`

## Remote
- `remote.rsync`
- `remote.ssh`
- `remote.scp`

## CI/CD
- `cicd.github_actions`
- `cicd.gitlab_ci`
- `cicd.jenkins`
- `cicd.circleci`

## Secrets
- `secrets.vault`
- `secrets.aws_secrets`
- `secrets.onepassword`
- `secrets.doppler`

## Platform
- `platform.github`
- `platform.gitlab`

## DNS
- `dns.cloudflare`
- `dns.route53`
- `dns.generic`

## Email
- `email.ses`
- `email.sendgrid`
- `email.mailgun`
- `email.postmark`

## Feature Flags
- `featureflags.flipt`
- `featureflags.launchdarkly`
- `featureflags.split`
- `featureflags.unleash`

## Load Balancer
- `loadbalancer.haproxy`
- `loadbalancer.nginx`
- `loadbalancer.traefik`
- `loadbalancer.elb`

## Monitoring
- `monitoring.splunk`
- `monitoring.datadog`
- `monitoring.pagerduty`
- `monitoring.newrelic`
- `monitoring.prometheus`

## Payments
- `payment.stripe`
- `payment.braintree`
- `payment.square`

## Messaging
- `messaging.kafka`
- `messaging.nats`
- `messaging.rabbitmq`
- `messaging.sqs_sns`

## Search
- `search.elasticsearch`
- `search.opensearch`
- `search.algolia`
- `search.meilisearch`

## Backup
- `backup.borg`
- `backup.rclone`
- `backup.restic`
- `backup.velero`

## Databases
- `database.postgresql`
- `database.mysql`
- `database.mongodb`
- `database.redis`
- `database.sqlite`

## Containers
- `containers.docker`
- `containers.compose`
- `containers.podman`

## Kubernetes
- `kubernetes.kubectl`
- `kubernetes.helm`
- `kubernetes.kustomize`

## Cloud
- `cloud.aws`
- `cloud.gcp`
- `cloud.azure`

## CDN
- `cdn.cloudflare_workers`
- `cdn.fastly`
- `cdn.cloudfront`

## API Gateway
- `apigateway.aws`
- `apigateway.kong`
- `apigateway.apigee`

## Infrastructure
- `infrastructure.terraform`
- `infrastructure.ansible`
- `infrastructure.pulumi`

## System
- `system.disk`
- `system.permissions`
- `system.services`

## Other
- `package_managers`
- `strict_git`

## Notes
- You can enable a whole category by specifying its prefix (e.g., `kubernetes`).
- Heredoc/inline-script scanning is configured under `[heredoc]`, not `[packs]`.
- See `docs/configuration.md` for full configuration details.
