# SKAdNetwork Postback Verify

This library helps to verify Apple SKAdNetwork postback data.

NOTE: It uses [forked](https://github.com/peak/certificate-transparency-go) version of [google/certificate-transparency-go](https://github.com/google/certificate-transparency-go) to parse Apple public keys.

```
import (
    https://github.com/peak/skanpostback
)

err := skanpostback.Verify(postbackDataBytes)
```