# jwt-cracker-go

jwt-cracker-go is a simple brute force cracker for HS256, HS384, and HS512 JWT tokens, inspired by jwt-cracker. It is effective for cracking JWT tokens with weak secrets.

jwt-cracker: <https://github.com/lmammino/jwt-cracker>

## Installation

To install jwt-cracker-go, you need to have Go installed on your machine.

```sh
go install github.com/elvisgraho/jwt-cracker-go@latest
```

## Usage

To use jwt-cracker-go, provide the following parameters:

* **-t** Specify the HMAC-SHA JWT token to crack (required).
* **-a** Define the alphabet to use for the brute force (optional).  
    Default - abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
* **-max** Set the maximum length of the secret (optional).
* **-f** Use a password file instead of brute force (optional).

### Examples

#### Brute Force Mode

```sh
jwt-cracker-go -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA -a "abcdefghijklmnopqrstuvwxyz" -max 8
```

#### Dictionary Mode

```sh
jwt-cracker-go -t your.jwt.token -f /path/to/password/file
```

### Comparison

Here is the comparison for secret: **aecre**  
**Token:** eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EhFb3dw98PWWVtDnWN7joeTQBhnE3Z3AnAFaQpbn358

| jwt-cracker-go  | jwt-cracker |
| ------------- | ------------- |
| 13.660 sec  | 257.501 sec  |

### License

jwt-cracker-go is open-sourced software licensed under the MIT license.
