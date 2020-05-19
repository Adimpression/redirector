# redirector

HTTP server that redirects requests


## Usage

The easiest way to run the redirector is using Docker.

Create a configuration file containing the redirections:

    cat <<. >redirector.yaml
    redirections:
      - host: example.org
        target: https://example.com
    .

See `etc/redirector.yaml` for a documented example configuration file.

Then start the redirector:

    docker run \
        -v $PWD/redirector.yaml:/etc/redirector.yaml:ro \
        -p 8000:80 \
        goabout/redirector

To test:

    curl localhost:8000 -Hhost:example.org
