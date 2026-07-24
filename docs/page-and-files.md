# Webpage and linked-file monitoring

The `page_and_files` processor keeps normal webpage text monitoring and adds
byte-level monitoring for downloadable files linked from that page. It is one
watch: linked files are not created as child watches.

On each check, the processor:

1. fetches and processes the webpage normally;
2. discovers links with common document/archive extensions or an HTML
   `download` attribute;
3. sends concurrent `HEAD` requests to those files;
4. streams a file through SHA-256 only on its first check, when its HTTP
   metadata changes or is unreliable, when `HEAD` is unsupported, or when the
   periodic verification interval is due; and
5. appends a stable linked-file inventory to the page snapshot so page and file
   changes use the existing history, diff, and notification path.

Downloaded bytes are not retained. Per-watch state is stored in
`linked_files.json` inside the watch's existing datastore directory.

Environment settings:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `LINKED_FILE_VERIFY_INTERVAL_SECONDS` | `604800` | Full SHA-256 backstop interval (seven days) |
| `LINKED_FILE_HEAD_WORKERS` | `8` | Maximum concurrent file checks per page |
| `LINKED_FILE_MAX_LINKS` | `200` | Maximum linked files checked from one page |
| `LINKED_FILE_MAX_BYTES` | `262144000` | Maximum bytes streamed for one file |

The stable snapshot records each file's URL, final URL, ETag, Last-Modified,
Content-Length, Content-Type, and SHA-256. A file addition, removal, metadata
change, checksum change, or persistent access error is therefore visible in the
normal page diff.
