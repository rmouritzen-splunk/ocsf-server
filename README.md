# Open Cybersecurity Schema Framework Server
This repository contains the Open Cybersecurity Schema Framework (OCSF) Schema Server source code.
The schema server is an HTTP server that provides a convenient way to browse and use the OCSF schema.

You can access the OCSF schema server, which is running the latest released schema, at [schema.ocsf.io](https://schema.ocsf.io).

The schema server can be also used locally. The server can be run as a container image or directly on your local machine.

## What's required to run locally
Both ways of running locally require the following:
- The `git` command line tool.
- Python 3.14 (or later) to run the OCSF schema compiler.

If you are developing the OCSF server and/or the OCSF schema, you will probably also want the GitHub `gh` command line tool. (There's apparently a GUI version of this as well.)

To run locally via a Docker image, [Docker Desktop](https://www.docker.com/products/docker-desktop/) is required. [Podman](https://podman.io/) may work as well, though not covered here as it does not run natively on macOS (the OS this author uses for development.)

To run locally directly, [Elixir](https://elixir-lang.org/) is required.

On macOS machines, all of these tools except Docker Desktop are available via [Homebrew](https://brew.sh).

In this document we are putting all of the OCSF GitHub organization repos in a `~/github/ocsf` directory. This is where we will be putting cloned repos that we will _use_. (This is specifics are matter taste, though in practice many developer use a pattern similar to this.) For development, creating forks in your own GitHub account is required (specifics are not covered here.)

## Cloning the server repo
Clone the [ocsf-server](https://github.com/ocsf/ocsf-server) repo.
```shell
mkdir -p ~/github/ocsf
cd ~/github/ocsf
git clone https://github.com/ocsf/ocsf-server.git
```

Note that building container images can be done directly against remove git repos. This is very similar, though not covered here.

## Building a server Docker image
Building using Docker Desktop is as follows. Here we build the server and tag it with `ocsf-server`.
```shell
cd ~/github/ocsf/ocsf-server
docker build -t ocsf-server .
```

## Compile an OCSF schema

### Clone the schema repo(s)
The OCSF Server from version 4 onwards requires a compiled schema created with browser mode enabled. Browser mode adds all of the extra bits required so references.

The un-compiled schema and any other extensions need to be cloned locally.

Clone the base schema repo. Here we clone the entire `ocsf/ocsf-schema` repo.

```shell
cd ~/github/ocsf
git clone https://github.com/ocsf/ocsf-schema.git
```

If you are developing the OCSF schema, the steps might be more like this:
```shell
cd ~/github/your-github-account-name
gh repo fork --clone ocsf/ocsf-schema
cd ocsf-schema
git checkout -b your-feature
```

You could also clone a specific version. Here we do that and use the `git clone` option `--single-branch`, which only downloads files related to the specific branch, so is faster and takes list disk space. Let's clone the `v1.6.0` release.

```shell
# Assuming we are already in our in the directory above where we put repos.
branch=v1.6.0
git clone --single-branch --branch $branch https://github.com/ocsf/ocsf-schema.git ocsf-schema-$branch
# This puts the v1.6.0 branch of the OCSF schema into ocsf-schema-v1.6.0
```

If you use a private schema, this should be cloned locally as well. Here we download the AWS extension at the `v1.0.0` tag. (The AWS extension is used as this is an actively used private extension publicly available in the GitHub OCSF organization.)

```shell
# Assuming we are already in our in the directory above where we put repos.
# Continuing from the example above, this is ~/github/ocsf.
branch=v1.0.0
git clone --single-branch --branch $branch https://github.com/ocsf/aws.git aws-$branch
# This puts the v1.0.0 branch of the AWS extension into aws-v1.0.0
```

### Install the OCSF schema compiler
Compiling schemas requires the [ocsf-schema-compiler](https://github.com/ocsf/ocsf-schema-compiler). This is a Python project published to PyPI: [ocsf-schema-compiler · PyPI](https://pypi.org/project/ocsf-schema-compiler/). The compiler can be used directly from its repo, however installation via `pip` should be easier. We will create a directory to install the compiler there and place compiled schemas. The example below uses `~/ocsf-compiled-schemas`. These steps assume Python 3.14 (or later) is installed and available via the `python3` command.

```shell
# Create a workspace to install the compiler and place compiled schemas
mkdir ~/ocsf-compiled-schemas
cd ~/ocsf-compiled-schemas
# Create a Python virtual environment
python3 -m venv .venv
# Activate the Python virtual environment
source .venv/bin/activate
# Install the compiler
pip install ocsf-schema-compiler
```

For later compilations, after activating the Python virtual environment updating the compiler is recommended.
```shell
cd ~/ocsf-compiled-schemas
# Activate the Python virtual environment
source .venv/bin/activate
# Update the compiler
pip install -U ocsf-schema-compiler
```

### Compiling a schema
These steps assume you are in a directory with the Python virtual environment activated and the compiler installed. The ocsf-schema-compiler compiled the various schema definition files to a single JSON object written to standard output. This needs to be piped to a file.

Being intended for the OCSF Server (the schema browser), these are all compiled with browser mode enabled, which is the `-b` or `--browser-mode` command-line option.

#### Compiling the base schema
This example will compile the current development schema cloned to `~/github/ocsf/ocsf-schema`.

```shell
ocsf-schema-compiler ~/github/ocsf/ocsf-schema -b > ocsf-schema-main-browser.json
```
The naming convention this author uses always starts with `ocsf-schema` (or just `schema`) then version (like `v1.6.0`) or branch (like `main`), then `-browser` if this is a browser mode compile.

As an aside, should you want to look at the compiled output, piping through the `jq` command line tool can be used to create a "pretty" version with sorted keys.
```shell
ocsf-schema-compiler ~/github/ocsf/ocsf-schema -b | jq -S > ocsf-schema-main-browser.json
```

The browser-mode version is, frankly, huge (over 45 megabytes). For viewing, you may want to use the "clean" version, which is the variation intended for by other downstream tools.

```shell
ocsf-schema-compiler ~/github/ocsf/ocsf-schema | jq -S > ocsf-schema-main.json
```

#### Compiling with an extension
The compiler allows compiling with any number of extensions.

A base schema's _platform extensions_ are included by default, but can be excluded with `-i`, `--ignore-platform-extensions` option. Platform extensions are those in the base schema's `extensions` directory.

Other extensions are specified using the compiler's `-e`, `--extensions-path` parameter followed by a path. This parameter can be used multiple times.

Let's compile OCSF Schema `v1.6.0` with AWS extension `v1.0.0`.
```shell
ocsf-schema-compiler ~/github/ocsf/ocsf-schema-v1.6.0 -e ~/github/ocsf/aws-v1.0.0 -b > ocsf-schema-v1.6.0-aws-v1.0.0-browser.json
```

Oops, this fails because the AWS extension defines a dictionary attribute named `last_used_time`, and the base schema also has a dictionary attribute with this name. This creates a shadowing situation where the extension can only use the version of the item defined in that extension. This can be confusing, so is not allowed by default. However, this situation can arise over time as items are added to the base schema that are named the same as one defined in an extension. The compiler turns this error into a warning with the `-a`, `--allow-shadowing` option.

```shell
ocsf-schema-compiler ~/github/ocsf/ocsf-schema-v1.6.0 -e ~/github/ocsf/aws-v1.0.0 -a -b > ocsf-schema-v1.6.0-aws-v1.0.0-browser.json
```

#### A note about extension processing order
The ocsf-schema-compiler processes extensions in a deterministic order as follows:
1. Platform extensions are processed in order of ascending extension unique identifiers.
2. Other extensions are processed in order of ascending extension unique identifiers.

Non-platform extensions (_private_ extensions) _should_ have unique identifiers higher than platform extension identifiers. The above rules ensure that the platform extensions are processed before private extensions even when this convention is not held.

## Running the OCSF server via a Docker image
To run, set the local directory for the volume to the directory holding the compiled schema to run against. The `SCHEMA_FILE` environment variable should be the compiled schema file relative to the volume mount directory, which is `/app/schemas` in this case.

```shell
docker run -it --rm --volume ~/ocsf-compiled-schemas:/app/schemas -e SCHEMA_FILE="/app/schemas/ocsf-schema-main-browser.json" -p 8080:8080 ocsf-server
```

To access the schema server, open [localhost:8080](http://localhost:8080) in your web browser.

## Local Usage
This section describes how to build and run the OCSF Schema server.

### Required build tools
The Schema server is written in [Elixir](https://elixir-lang.org) using the [Phoenix](https://phoenixframework.org/) Web framework.

The Elixir site maintains a great installation page, see https://elixir-lang.org/install.html for help.

### Building the schema server
Elixir uses the [`mix`](https://hexdocs.pm/mix/Mix.html) build tool, which is included in the Elixir installation package.

#### Install the build tools
```shell
mix local.hex --force && mix local.rebar --force
```

#### Get the dependencies
Clone the repo using the `git` or `gh` tool. The examples below assume the OCSF server has been cloned to `~/github/ocsf/ocsf-server`.

```shell
cd ~/github/ocsf/ocsf-server
mix deps.get
```

#### Compile the source code
```shell
mix compile
```

### Running the schema server
You can use the Elixir's interactive shell, [IEx](https://hexdocs.pm/iex/IEx.html). The server will look for the compiled schema with the `SCHEMA_FILE` environment variable.

For example, using the schema compiled from the main main branch as above, this is how you can run the server:

```shell
SCHEMA_FILE=~/ocsf-compiled-schemas/ocsf-schema-main-browser.json iex -S mix phx.server
```

Or if you prefer using separate lines:

```shell
export SCHEMA_FILE=~/ocsf-compiled-schemas/ocsf-schema-main-browser.json
iex -S mix phx.server
```

The OCSF Server (the Schema Browser) can then be accessed by browsing [`localhost:8080`](http://localhost:8080).

### Reloading the schema
You can use the following command in the `iex` shell to force reloading the current compiled schema file, or a different one.

To reload the current compiled schema file:
```elixir
Schema.reload()
```

To reload a different compiled schema file:
```elixir
Schema.reload("/path/to/compiled/schema.json")
```

## Runtime configuration
The schema server uses a number of environment variables.

| Variable Name    | Description |
| ---------------- | ----------- |
| HTTP_PORT        | The server HTTP  port number, default: `8080`|
| SCHEMA_FILE      | The path to the compiled schema file. |
| SCHEMAS_DIR      | The directory containing various schemas. Each subdirectory must contain a `version.json` file. |

## Running against multiple versions of the schema
The OCSF Server does not directly support hosting multiple versions. To present multiple version, each version is hosted by a different instance of the server, with support from a small amount of code to enable finding alternate versions and switching to other instances. The public OCSF Server does this by fronting the web site with Nginx and running each server instance in separate Docker containers.

The following answer in this repo's discussions area covers the gory details:
* [How can you run this server with more than one schema version? #131](https://github.com/ocsf/ocsf-server/discussions/131).

Much if this is relevant for the current version of the server. The approach is quite complicated and is only getting more complex over time as more and more schema versions are released. Supporting the older v3 and current v4 server at the same time adds even more complication. It's complication on top of complication.

Should anyone need this information, it will be added here. Ask via the the Slack server or create an [ocsf-server issue](https://github.com/ocsf/ocsf-server/issues).
