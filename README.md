# redirector

HTTP server that redirects requests


## Usage

Create a configuration file containing the redirections:

    cat <<. >redirector.yaml
    redirections:
      - host: example.eu
        target: https://example.com
        status: 301
      - hosts:
        - user.example.com
        - users.example.com
        target: https://example.com/users/
    .
    
Then start the redirector:

    redirector --config redirector.yaml

In production, it is useful to write the logs in JSON format:

    redirector --config=redirector.yaml --log-format=json
    
Use the help function for all options:

    redirector --help 
