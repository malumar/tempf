# tempf - Temporary File Storage Server

**tempf** is a lightweight HTTP server designed for temporary file storage. It allows users to easily upload files via simple `curl` commands. The application includes built-in API key authorization, which lets you control file access—files can either be publicly accessible or password-protected for secure downloads.

tempf supports setting expiration dates for files, automatically deleting them once their lifespan expires. You can create and organize nested folders, as well as delete files and folders individually or in bulk using patterns with `*` and `?`. Access to file and folder lists can be fully public or restricted based on path patterns, which can be configured through application flags.

## Flags in tempf:

1. **`-path`** (string): Specifies the configuration folder. If left empty, it defaults to the folder where the application is running.
    - Example: `-path /etc/tempf`

2. **`-disable`** (string): Disables specific handlers. Provide a list of handler names separated by commas.
    - Example: `-disable upload,delete`

3. **`-resetkey`** (bool): Resets the API key used for file upload authorization.
    - Example: `-resetkey`

4. **`-maxuploadsize`** (int64): Sets the maximum upload size in bytes. A value of 0 means no limit.
    - Default: 10 MB
    - Example: `-maxuploadsize 20971520` (20 MB)

5. **`-maxmemstore`** (int64): Defines the maximum file size (in bytes) to be stored in memory rather than the database. A value of 0 means the file is never stored in the database.
    - Example: `-maxmemstore 512000` (500 KB)

6. **`-run`** (bool): Starts the server.
    - Example: `-run`

7. **`-allowlist`** (slice): A pattern-based allowlist (using `*` and `?`) to control which files can be listed publicly in the absence of authorization.
    - Example: `-allowlist "*.jpg" -allowlist "docs/*"`

## Example Configuration

```bash
tempf -path /etc/tempf -disable upload,delete -maxuploadsize 20971520 -run
```

## Example: Uploading a File with Expiry and Password using curl

The **tempf** server allows users to upload files using curl. Files can be uploaded with optional parameters such as file expiration time, custom comments, and password protection via the hash parameter.

```bash
curl -v -X POST -H "Authorization: Bearer <API_KEY>" \
-F "file=@/path/to/file.txt" \
"http://<server_address>/upload/yourfilename?expire=1day&hash=yourpassword&comment=TestFileUpload"
```

### Breakdown of the Command:
- -X POST: Initiates a POST request to upload the file.
- -H "Authorization: Bearer <API_KEY>": Adds the API key for authentication. Replace <API_KEY> with the actual key.
- -F "file=@/path/to/file.txt": Specifies the file to be uploaded. The @symbol is used to upload the file located at /path/to/file.txt.
- "http://<server_address>/upload/yourfilename?expire=1day&hash=yourpassword&comment=TestFileUpload": URL where the file will be uploaded. Replace
    - <server_address> with the server address.
    - yourfilename is the name the file will have on the server.
    - expire=1day (or year,month,week,day,hour,minute and second) sets the file to expire after one day. Skip if You don't want use expiration time.
    - hash=yourpassword adds password protection for file download.
    - comment=TestFileUpload adds a comment to the file.

#### Example

```bash
curl -v -X POST -H "Authorization: Bearer myapikey123" \
-F "file=@/home/user/test.txt" \
"http://localhost:8080/upload/testfile?expire=1week&hash=securepassword&comment=ImportantUpload"
```


## Methods

### Method: List

The `List` method in the **tempf** server is used to retrieve a list of files and folders that match a specific pattern. It supports wildcard characters (`*` for multiple characters and `?` for a single character) for flexible file and folder matching. Access to the file list is secured by an API key and can be restricted based on path patterns.

#### Endpoint:

GET /list/{path}


#### Authorization:

- The `Authorization` header must contain a valid API key for listing files.
    - Example: `Authorization: Bearer <API_KEY>`

#### Parameters:

- **`path`**: (required) The folder path or filename to list. Can contain wildcards (`*` and `?`).
    - Example: `/list/john/invoices`
    - Example with wildcards: `/list/john/invoices/*`

- **`include`**: (optional) Filters to include specific file types:
    - `file`: Only include files in the listing.
    - `folder`: Only include folders in the listing.
    - Example: `/list/john/invoices?include=file`

- **`limit`**: (optional) Limits the number of results returned.
    - Example: `/list/john/invoices?limit=10`

#### Example Request:

```bash
curl -X GET -H "Authorization: Bearer <API_KEY>" \
"http://<server_address>/list/john/invoices?include=file&limit=10"
```

#### Example Response

```json
[
  {
    "key": "john/invoices/2024/07/invoice1.pdf",
    "fileInfo": {
      "size": 102400,
      "lastModified": "2024-07-01T12:00:00Z",
      "type": "file"
    }
  },
  {
    "key": "john/invoices/2024/07/invoice2.pdf",
    "fileInfo": {
      "size": 204800,
      "lastModified": "2024-07-01T12:30:00Z",
      "type": "file"
    }
  }
]
```

### Method: Upload

The `Upload` method in the **tempf** server allows users to upload files with optional parameters such as expiration, comments, and password protection (via a hash). Access is secured using an API key.

#### Endpoint:

POST /upload/{filename_with_path}


#### Authorization:

- The `Authorization` header must contain a valid API key for uploading files.
    - Example: `Authorization: Bearer <API_KEY>`

#### Parameters:

- **`filename_with_path`**: (required) The name and path where the file should be saved on the server.
    - Example: `/upload/docs/myfile.txt`

- **`name`**: (optional) Original name of the file being uploaded.
    - Example: `name=myfile.txt`

- **`comment`**: (optional) A comment or description to attach to the uploaded file.
    - Example: `comment=MyDocument`

- **`expire`**: (optional) The expiration time for the file. Use a numerical value followed by `year`, `month`, `week`, `day`, `hour`, `minute`, or `second`.
    - Example: `expire=1day`

- **`hash`**: (optional) A password to protect the file from public access.
    - Example: `hash=securepassword`

#### Example Request:

```bash
curl -v -X POST -H "Authorization: Bearer <API_KEY>" \
-F "file=@/path/to/file.txt" \
"http://<server_address>/upload/myfile?name=myfile.txt&expire=1day&hash=securepassword&comment=ImportantFile"
```

### Request Headers (Optional):

- X-Original-Name: Sets the original name of the file.
- X-Comment: Adds a comment or description to the file.
- X-Expire-After: Sets the file expiration time.
- X-Hash: Provides a hash for password protection.

If values are provided both in the URL and the headers, the header values take precedence.

###  Response Codes:

- 200 OK: File was successfully uploaded and saved.
- 400 Bad Request: Incorrect HTTP method or invalid request parameters.
- 401 Unauthorized: Authorization token is missing or incorrect.
- 422 Unprocessable Entity: Invalid file upload (e.g., content size is zero, or exceeds limit).
- 501 Internal Server Error: An internal server error occurred.

#### Example Response

```json
{
  "message": "file uploaded successfully",
  "file_key": "docs/myfile.txt",
  "size": 102400,
  "expire_after": "1day"
}
```

In this example, the file myfile.txt is uploaded, with an expiration time of 1 day and password protection.

### Method: Download

The `Download` method in the **tempf** server allows users to download files. The method supports optional password protection via a hash, which must be provided if the file was protected during upload. Access is secured by an API key or by the file's hash if it was set.

#### Endpoint:

GET /download/{filename_with_path}


#### Authorization:

- The `Authorization` header must contain a valid API key, or the request must include the correct hash if the file was protected.
    - Example: `Authorization: Bearer <API_KEY>`

#### Parameters:

- **`filename_with_path`**: (required) The path and filename of the file to download.
    - Example: `/download/docs/myfile.txt`

- **`hash`**: (optional) If the file was protected by a hash during upload, you must provide the correct hash.
    - Example: `hash=securepassword`

#### Example Request:

```bash
curl -X GET -H "Authorization: Bearer <API_KEY>" \
"http://<server_address>/download/docs/myfile.txt?hash=securepassword"
```

### Request Headers (Optional):

- X-Hash: If the file was protected with a hash during upload, the hash can be provided in the headers instead of the URL.
    - Example: X-Hash: securepassword

If both the hash is provided in the URL and in the headers, the header value takes precedence.

### Response Codes:

- 200 OK: File was successfully downloaded.
- 400 Bad Request: Incorrect HTTP method or invalid request parameters.
- 401 Unauthorized: Authorization token is missing or incorrect.
- 404 Not Found: File not found or has expired.
- 422 Unprocessable Entity: Invalid parameters (e.g., incorrect hash).
- 501 Internal Server Error: An internal server error occurred.

### Method: Remove

The `Remove` method in the **tempf** server is used to delete a single file from the server. This method requires bearer token authorization for security. It only removes individual files, not directories. If you want to delete an entire directory, use the `RemoveAll` method.

#### Endpoint:

GET /remove/{filename_with_path}


#### Authorization:

- The `Authorization` header must contain a valid API key to authorize the file deletion.
    - Example: `Authorization: Bearer <API_KEY>`

#### Parameters:

- **`filename_with_path`**: (required) The path and filename of the file to remove.
    - Example: `/remove/docs/myfile.txt`

#### Example Request:

```bash
curl -X GET -H "Authorization: Bearer <API_KEY>" \
"http://<server_address>/remove/docs/myfile.txt"
```

### Response Codes:
- 200 OK: File was successfully removed.
- 400 Bad Request: Incorrect HTTP method or invalid request parameters.
- 401 Unauthorized: Authorization token is missing or incorrect.
- 404 Not Found: File not found or has expired.
- 422 Unprocessable Entity: The provided path is incorrect (e.g., trying to remove a directory instead of a file).
- 501 Internal Server Error: An internal server error occurred.

### Method: RemoveAll

The `RemoveAll` method in the **tempf** server is used to recursively delete a directory, including all subdirectories and files within it. This method requires bearer token authorization for security and supports wildcards (`*` and `?`) to match specific files or folders.

#### Endpoint:

GET /removeall/{directory_with_path}/


#### Authorization:

- The `Authorization` header must contain a valid API key to authorize the directory deletion.
    - Example: `Authorization: Bearer <API_KEY>`

#### Parameters:

- **`directory_with_path`**: (required) The path to the directory you want to delete. Can contain wildcards for flexible matching.
    - Example: `/removeall/docs/old_files/`
    - Example with wildcards: `/removeall/docs/*`

#### Example Request:

```bash
curl -X GET -H "Authorization: Bearer <API_KEY>" \
"http://<server_address>/removeall/docs/old_files/*"
```

### Response Codes:
- 200 OK: Directory and its contents were successfully removed.
- 400 Bad Request: Incorrect HTTP method or invalid request parameters.
- 401 Unauthorized: Authorization token is missing or incorrect.
- 404 Not Found: Directory or file not found or has expired.
- 422 Unprocessable Entity: Invalid parameters (e.g., trying to remove a non-existent directory).
- 501 Internal Server Error: An internal server error occurred.