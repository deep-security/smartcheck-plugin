# Deep Security Smart Check plugin for Jenkins

Provides Jenkins integration with [Deep Security Smart Check][]

[deep security smart check]: https://www.trendmicro.com/smartcheck

## Installation

1. Download the `hpi` file from the
   [releases page](https://github.com/deep-security/smartcheck-plugin/releases)
2. Install this plugin on your Jenkins server:
   1. From the Jenkins homepage navigate to "Manage Jenkins"
   2. Navigate to "Manage Plugins"
   3. Change the tab to "Advanced"
   4. Under the "Upload Plugin" select the `hpi` file we downloaded earlier.

## Usage

In your pipeline script:

```groovy
withCredentials([
    usernamePassword([
        credentialsId: "example-registry-auth",
        usernameVariable: "REGISTRY_USER",
        passwordVariable: "REGISTRY_PASSWORD",
    ])
]){
    smartcheckScan([
        imageName: "registry.example.com/my-project/my-image",
        smartcheckHost: "smartcheck.example.com",
        smartcheckCredentialsId: "smartcheck-auth",
        imagePullAuth: new groovy.json.JsonBuilder([
            username: REGISTRY_USER,
            password: REGISTRY_PASSWORD,
        ]).toString(),
    ])
}
```

### Parameters

- **smartcheckHost**
  - The hostname of the Deep Security Smart Check deployment. Example:
    `smartcheck.example.com`
- **insecureSkipTLSVerify**
  - If the client should ignore certificate errors when connecting to Deep
    Security Smart Check. You may want to set this if you've configured a self
    signed cert.
- **smartcheckCredentialsId**
  - The credentials to authenticate with the Deep Security Smart Check deployment.
    This must be a "Username with password" credential.
- **imageName**
  - The name of the image to scan
- **imagePullAuth**

  - A JSON object of credentials for authenticating with the registry to pull
    the image from. Example:

    ```groovy
    smartcheckScan([
        imagePullAuth: new groovy.json.JsonBuilder([
            username: REGISTRY_USER,
            password: REGISTRY_PASSWORD,
        ]).toString(),
        //...
    ])
    ```

    See [creating a scan][] in the [Deep Security Smart Check API Reference][]
    for additional registry credentials options.

[deep security smart check api reference]:
  https://deep-security.github.io/smartcheck-docs/api/index.html
[creating a scan]:
  https://deep-security.github.io/smartcheck-docs/api/index.html#operation/createScan

- **insecureSkipRegistryTLSVerify**
  - If Deep Security Smart Check should ignore certificate errors from the image
    registry.
- **preregistryScan**
  - Specify this option to trigger a "pre-registry scan", which pushes the image
    to a temporary registry on the scan system.
- **preregistryHost**
  - The hostname of the temporary registry. Defaults to the `smartcheckHost` on
    port 5000.
- **preregistryUser**
  - The username to authenticate with the temporary registry.
- **preregistryPassword**
  - The password to authenticate with the temporary registry.
- **resultsFile** - default: `scan-results.json`
  - The path to write the scan results to
- **findingsThreshold**

  - A JSON object that can be used to fail this step if an image contains
    findings that exceed the threshold.

    Example with default values:

    ```groovy
    smartcheckScan([
        //...
        findingsThreshold: new groovy.json.JsonBuilder([
            malware: 0,
            vulnerabilities: [
                defcon1: 0,
                critical: 0,
                high: 0,
            ],
            contents: [
                defcon1: 0,
                critical: 0,
                high: 0,
            ],
            checklists: [
                defcon1: 0,
                critical: 0,
                high: 0,
            ],
        ]).toString(),
    ])
    ```

    Schema:

    ```typescript
    interface FindingsThreshold {
      malware?: number;
      contents?: {
        defcon1?: number;
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        negligible?: number;
        unknown?: number;
      };
      vulnerabilities?: {
        defcon1?: number;
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        negligible?: number;
        unknown?: number;
      };
      checklists?: {
        defcon1?: number;
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        negligible?: number;
        unknown?: number;
      };
    }
    ```

## Pre-registry scanning

Deep Security Smart Check can scan your images before they are pushed to your
production registry. If you have enabled pre-registry scanning on your Deep
Security Smart Check instance, you can add the `preregistryScan`,
`preregistryUser`, and `preregistryPassword` parameters to the `smartcheckScan`
method:

```groovy
withCredentials([
    usernamePassword([
        credentialsId: "preregistry-auth",
        usernameVariable: "PREREGISTRY_USER",
        passwordVariable: "PREREGISTRY_PASSWORD",
    ])
]){
    smartcheckScan([
        imageName: "registry.example.com/my-project/my-image",
        smartcheckHost: "smartcheck.example.com",
        smartcheckCredentialsId: "smartcheck-auth",
        preregistryScan: true,
        preregistryUser: PREREGISTRY_USER,
        preregistryPassword: PREREGISTRY_PASSWORD,
    ])
}
```

## Development

See [DEVELOPMENT.md](./DEVELOPMENT.md) for instructions on getting started.

## Contributing

If you encounter a bug, think of a useful feature, or find something confusing
in the docs, please
[create a new issue](https://github.com/deep-security/smartcheck-plugin/issues/new)!

We :heart: pull requests. If you'd like to fix a bug, contribute to a feature or
just correct a typo, please feel free to do so.

If you're thinking of adding a new feature, consider opening an issue first to
discuss it to ensure it aligns to the direction of the project (and potentially
save yourself some time!).

## Support

Official support from Trend Micro is not available. Individual contributors may
be Trend Micro employees, but are not official support.
