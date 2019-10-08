## Zeek Plugin TDS

When running as part of your Zeek installation this plugin will produce three log files containing metadata extracted from any [Tabular Data Stream](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec) (TDS) traffic observed on TCP port 1433.

## Installation and Usage

`zeek-plugin-tds` is distributed as a Zeek package and is compatible with the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command line tool.

## Sharing and Contributing

This code is made available under the [BSD-3-Clause license](LICENSE). [Guidelines for contributing](CONTRIBUTING.md) are available as well as a [pull request template](.github/PULL_REQUEST_TEMPLATE.md). A [Dockerfile](Dockerfile) has been included in the repository to assist with setting up an environment for testing any changes to the plugin

.


