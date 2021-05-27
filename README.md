# clambake
A python application to analyze container images for Viruses using ClamAV.

# development env

Run the following from the root of this repo to start an env for local development

```
docker run \
    -it --rm \
    -v $(pwd):/opt/clambake \
    -v /var/run/docker.sock:/var/run/docker.sock \
    $(docker build -q .) \
        bash
```