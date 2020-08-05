[![BuildStatus](https://travis-ci.org/google/capirca.svg?branch=master)](https://travis-ci.org/google/capirca)
# Capirca

Capirca is a tool designed to utilize common definitions of networks, services and high-level policy files to facilitate the development and manipulation of network access control lists (ACLs) for various platforms. It was developed by Google for internal use, and is now open source.

To install the dev environment in machines that support bash files, run the `dev-install` script provided.

```bash
$ dev-install
```

## Community
Capirca has a channel on the [NetworkToCode slack](https://networktocode.slack.com/).


## Running with Docker
If your usecase is to just use the CLI and you don't want to go through the process of installing Capirca, you can use the dockerized version. Just pipe your CLI arguments onto the container instead and mount your working directory to the `/data` directory of the container!

Example:

```bash
$ docker run -v "${PWD}:/data" docker.pkg.github.com/google/capirca/capirca:latest
```
