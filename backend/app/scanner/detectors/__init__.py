from . import api, authentication, cookies, cors, csrf, directory, disclosure, exposure, headers

PASSIVE = (headers.detect, cookies.detect, cors.detect, csrf.detect, directory.detect,
           disclosure.detect, authentication.detect, api.detect, exposure.detect)
