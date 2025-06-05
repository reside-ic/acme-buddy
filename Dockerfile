FROM goacme/lego

# The lego base image uses Alpine as its distro, hence the use of apk as
# the package manager
RUN apk add --no-cache python3 py3-requests

COPY lego-hdb-plugin.py /usr/local/bin/lego-hdb-plugin

ENV EXEC_PATH="/usr/local/bin/lego-hdb-plugin"
ENV EXEC_PROPAGATION_TIMEOUT=210

# ICT makes the _acme-challenge record a CNAME, and by default Lego follows
# that CNAME and tries to update the underlying record. That's not what we
# want, so this disables that behaviour.
ENV LEGO_DISABLE_CNAME_SUPPORT="true"
