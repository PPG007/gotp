# gotp

This repository implements TOTP and HOTP generation that defined in [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238) and [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226)。

## Install

```shell
go get github.com/PPG007/gotp
```

## Usage

### Generate TOTP

```go
func main() {
	secret := make([]byte, 10)
	n, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(gotp.NewTOTP(
		gotp.WithSecret(secret[:n]),
	).SignPassword())
}
```

### Generate HOTP

```go
func main() {
	secret := make([]byte, 10)
	n, err := rand.Read(secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(gotp.NewHOTP(
		gotp.WithSecret(secret[:n]),
	).SignPassword())
}
```

### With Config

`NewHOTP()` and `NewTOTP()` have same options, you can set options by `with` methods:

```go
fmt.Println(gotp.NewHOTP(
    gotp.WithSecret(secret[:n]),
    gotp.WithCounter(1),
    gotp.WithDigits(10),
    gotp.WithAlgorithm(gotp.ALGORITHM_SHA512),
).SignPassword())
```

### Sign otpauth url

gotp also support otpauth url generation:

```go
fmt.Println(gotp.NewHOTP(
    gotp.WithSecret(secret[:n]),
).SignURL())
```
You can specify label and issuer in the url:

```go
fmt.Println(gotp.NewHOTP(
    gotp.WithSecret(secret[:n]),
    gotp.WithLabel("PPG007"),
    gotp.WithIssuer("PPG007"),
).SignURL())
```
