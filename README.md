# III-IV: Opinionated framework for web services

III-IV is a rudimentary and _very_ opinionated framework to build web services
in Rust.  This framework is a thin layer over other well-known crates such as
`axum` and `sqlx`.  As such, it mostly provides boilerplate code necessary to
tie everything together, but it also forces code to be structured in a way
that permits fast unit testing.

At the moment, all of the functionality and structure provided here are geared
towards the way **I, @jmmv**, have been building these web services.  The vast
majority of the code in this repository comes from those services verbatim and
is quite ad-hoc.  So... take this as a disclaimer: _I don't think that the
code in here will be readily usable for your use case.  This is why there are
no formal releases nor plans to make them, and there are zero promises about
backwards API compatibility: there will be churn._

That said, if you find this useful for any reason and want to use portions of
the code anyway, great!  You will have to pull the code from Git, read the doc
comments attached to the various crates and modules, and I strongly recommend
that you pin your usage to a specific commit.  I'll be happy to consider
contributions if you have any.

## Key characteristics

*   High-level transaction-based database abstraction, which provides a
    mechanism to implement the exact same service logic against PostgreSQL and
    SQLite.
*   Use of PostgreSQL in deployment builds and SQLite during testing, thanks to
    the prior point.
*   Proven foundations: `sqlx` for database access, `axum` as the web framework,
    and `tokio` as the async runtime.
*   Configuration via environment variables.
*   Optional deployment to Azure functions.

## What's in the name?

The name III-IV refers to the number of layers that services using this
framework need to implement.  The 3 is about the `rest`, `driver`, and `db`
layers, and the 4 is about the cross-layer data `model` module.  You can read
the name as "three-four".

## Installation

As mentioned in the introduction above, there are no formal releases of this
framework and there are no plans to make them.  You will have to depend on this
code straight from this Git repository.

The following can get you started.  Make sure to pick the latest commit
available in this repository to pin your dependencies to.  Do _not_ rely on
the `main` branch.

```toml
[dependencies.iii-iv-core]
git = "https://github.com/jmmv/iii-iv.git"
rev = "git commit you based your work off"

[dependencies.iii-iv-postgres]
git = "https://github.com/jmmv/iii-iv.git"
rev = "git commit you based your work off"

[dev-dependencies.iii-iv-core]
git = "https://github.com/jmmv/iii-iv.git"
rev = "git commit you based your work off"
features = ["testutils"]

[dev-dependencies.iii-iv-postgres]
git = "https://github.com/jmmv/iii-iv.git"
rev = "git commit you based your work off"
features = ["testutils"]

[dev-dependencies.iii-iv-sqlite]
git = "https://github.com/jmmv/iii-iv.git"
rev = "git commit you based your work off"
features = ["testutils"]
```

## Example

The `example` directory contains a full application built using this framework.
The application implements a simple REST interface for a key/value store.  The
server is backed by PostgreSQL in the binary build, but tests are backed by
SQLite.  This allows tests to run at lightning speeds and with zero setup, which
is a primary goal of this framework.

The code of the application is overly verbose: you will notice that there are
many small files.  This is to make room for tests at every layer (which you will
also find in the template), because the tests tend to grow up very large.

This example is meant to be usable as a template for new services.  You can
copy/paste it into a new crate, delete all of the key/value store logic, and
add your own.
