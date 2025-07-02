[![REUSE status](https://api.reuse.software/badge/github.com/cap-java/cds-feature-auditlog-ng)](https://api.reuse.software/info/github.com/cap-java/cds-feature-auditlog-ng)

> [!WARNING]
> The publishing process of this repository is still in progress.

# cds-feature-auditlog-ng

## About this project

The Audit Log Service NG Java CAP plugin enables Java CAP applications to emit audit log events in a standardized way. It is fully compatible with the [Audit Log Event Catalog](https://github.tools.sap/wg-observability/telemetry-semantic-conventions/tree/audit-log-events?tab=readme-ov-file#event-catalog), ensuring standardized event semantics and compatibility. 

You can emit the following types of audit log events:
- Personal Data Access Event
- Personal Data Modification Event
- Configuration Change Event
- Security Event

Official CAP documentation can be found [here](https://pages.github.tools.sap/cap/docs/java/auditlog).

# Consumption

To consume the Audit Log Service NG, follow these steps:

1. Complete the onboarding [process](https://jira.tools.sap/browse/ALSREQ-163).
2. Create a [user-provided service instance](https://docs.cloudfoundry.org/devguide/services/user-provided.html) in Cloud Foundry with the following credentials:

```json
{
  "url": "als-endpoint",
  "region": "als-region",
  "namespace": "registered namespace",
  "cert": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "key": "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----",
  "passphrase": "private key pass phrase" // optional
}
```

Example command:
```sh
cf cups auditlog-ng -p '{
  "url": "https://your-als-endpoint",
  "region": "your-region",
  "namespace": "your-namespace",
  "cert": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "key": "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----",
  "passphrase": "your-passphrase"
}' -t auditlog-ng
```

3. Bind the user-provided service instance to your application:
```
cf bind-service <your-app-name> auditlog-ng
```

4. Add the Maven Dependency
```xml
<dependency>
	<groupId>com.sap.cds</groupId>
	<artifactId>cds-feature-auditlog-ng</artifactId>
	<version>auditlog-ng.version</version> <!-- e.g 1.0.4-SNAPSHOT --> 
</dependency>
```

# Testing

For both local and cloud testing, refer to the [cloud-cap-samples-java](https://github.com/SAP-samples/cloud-cap-samples-java) repository and follow the instructions provided in its README.

For local testing, make sure to create a default-env.json file at the root of your project. This file should contain the following content:

```json
{
  "VCAP_SERVICES": {
    "application-logs": [
      {
        "binding_guid": "binding_guid",
        "binding_name": null,
        "credentials": {},
        "instance_guid": "instance_guid",
        "instance_name": "cf-logging",
        "label": "application-logs",
        "name": "cf-logging",
        "plan": "lite",
        "provider": null,
        "syslog_drain_url": null,
        "tags": [],
        "volume_mounts": []
      }
    ],
    "user-provided": [
      {
        "binding_guid": "binding_guid",
        "binding_name": null,
        "credentials": {
          "url": "als-endpoint",
          "region": "als-region",
          "namespace": "registered namespace",
          "cert": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
          "key": "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----",
          "passphrase": "private key pass phrase"
        },
        "instance_guid": "instance_guid",
        "instance_name": "auditlog-ng",
        "label": "user-provided",
        "name": "auditlog-ng",
        "syslog_drain_url": null,
        "tags": [
          "auditlog-ng"
        ],
        "volume_mounts": []
      }
    ]
  },
  "VCAP_APPLICATION": {
    "application_id": "application_id",
    "application_name": "bookshop-srv",
    "application_uris": [
      "application_uris"
    ],
    "cf_api": "cf_api",
    "limits": {
      "fds": 32768
    },
    "name": "bookshop-srv",
    "organization_id": "organization_id",
    "organization_name": "organization_name",
    "space_id": "space_id",
    "space_name": "space_name",
    "uris": [
      "application_uris"
    ],
    "users": null
  }
}
```

This file simulates the Cloud Foundry environment variables required for your application to run locally.


## Requirements and Setup

*Insert a short description what is required to get your project running...*

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/cap-java/cds-feature-auditlog-ng/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Security / Disclosure
If you find any bug that may be a security problem, please follow our instructions at [in our security policy](https://github.com/cap-java/cds-feature-auditlog-ng/security/policy) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/cap-java/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and cds-feature-auditlog-ng contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/cap-java/cds-feature-auditlog-ng).
