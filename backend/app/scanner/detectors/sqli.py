import re
from urllib.parse import parse_qsl, urlsplit

from .base import finding
from .reflection import mutate


ERROR = re.compile(r'(SQL syntax.*MySQL|unclosed quotation mark|ORA-\d{5}|SQLSTATE\[|SQLite.*(?:syntax|error)|PostgreSQL.*ERROR)', re.I)


async def probe(transport, r):
    if ERROR.search(r.text):
        return []
    output = []
    for key, value in dict(parse_qsl(urlsplit(r.url).query, keep_blank_values=True)).items():
        response = await transport.request(mutate(r.url, key, value + "'"))
        if ERROR.search(response.text):
            item = finding(response, 'sqli', 'Database error introduced by quote-only input', 'Medium',
                           'A single quote introduced a recognizable database error absent from the baseline.',
                           'An error does not prove SQL injection. No extraction, timing, UNION or modification payloads were used.',
                           'Use parameterized queries and avoid returning database errors.', {'parameter': key, 'input_change': 'append one apostrophe'})
            output.append(item)
    return output
