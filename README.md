# SKAdNetwork Postback Verify

This library helps to verify Apple SKAdNetwork postback data.

```
import (
    https://github.com/peak/skanpostback
)

err := skanpostback.Verify(postbackDataBytes)
```

NOTE: It uses [forked](https://github.com/peak/certificate-transparency-go) version of [google/certificate-transparency-go](https://github.com/google/certificate-transparency-go) to parse Apple public keys. 
So you should run below command to add replace setting to your own go.mod file:

```
go mod edit -replace="github.com/google/certificate-transparency-go@v1.1.1=github.com/peak/certificate-transparency-go@v0.0.0-p192"
```
