# jwt-cracker-go

A fast JWT token cracker that supports multiple algorithms and cracking methods. Built in Go.

## Features

- **Multiple Algorithms**: Supports HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
- **Cracking Methods**:
  - Brute force with custom alphabet and max length
  - Dictionary attack with password files
  - Pattern-based cracking
- **Token Analysis**: Analyzes tokens for security issues
- **Secret Generation**: Generates common JWT secrets
- **Progress Tracking**: Real-time progress with ETA
- **Parallel Processing**: Multi-core support for faster cracking

## Installation

```bash
go install github.com/elvisgraho/jwt-cracker-go@latest
```

## Usage

### Basic Usage

```bash
jwt-cracker-go -t <jwt_token> [options]
```

### Options

- `-t`: JWT token to crack (required)
- `-a`: Alphabet for brute force (default: a-zA-Z0-9)
- `-max`: Maximum secret length (default: 12)
- `-f`: Password file for dictionary attack
- `-p`: Pattern for secret generation (base64, hex, uuid, email, date, ip)
- `-alg`: Specify JWT algorithm
- `-analyze`: Analyze token for security issues
- `-generate`: Generate common JWT secrets
- `-o`: Output file for results
- `-v`: Verbose output
- `-c`: Number of concurrent workers (0 = CPU count)
- `-batch`: Batch size for processing (0 = auto)
- `-force`: Force cracking even if token is invalid

### Examples

1. Brute force attack:
```bash
jwt-cracker-go -t eyJhbGciOiJIUzI1NiIs... -max 8
```

2. Dictionary attack:
```bash
jwt-cracker-go -t eyJhbGciOiJIUzI1NiIs... -f passwords.txt
```

3. Analyze token:
```bash
jwt-cracker-go -t eyJhbGciOiJIUzI1NiIs... -analyze
```

4. Generate secrets:
```bash
jwt-cracker-go -generate -o secrets.txt
```

5. Pattern-based cracking:
```bash
jwt-cracker-go -t eyJhbGciOiJIUzI1NiIs... -p base64
```

## Performance

- Multi-core parallel processing
- Efficient batch processing
- Memory-optimized for large dictionaries
- Progress tracking with ETA

## License

MIT License
