# OCSF Types

The `ocsf` package holds the **storage-side** representation of OCSF events. The OCSF
standard itself — generated event/object structs, classification constants, enum caption
maps, and the class-UID registry — lives in
[ocsf-schema-go](https://github.com/grokify/ocsf-schema-go).

## Package

```go
import (
    "github.com/grokify/ocsf-lake/pkg/ocsf"          // storage envelope
    "github.com/grokify/ocsf-schema-go/ocsf/events"  // OCSF standard: events, constants
    "github.com/grokify/ocsf-schema-go/ocsf/objects" // OCSF standard: objects
)
```

## StoredEvent

Represents an OCSF event as stored in the data lake: the original payload plus storage
metadata and indexed classification columns.

```go
type StoredEvent struct {
    ID string

    // OCSF classification fields (indexed)
    ClassUID    int
    CategoryUID int
    ActivityID  int
    TypeUID     int
    SeverityID  int
    StatusID    int

    Time       int64     // OCSF event time (epoch ms)
    IngestedAt time.Time // when the lake received it

    Source        string
    SchemaVersion string

    Payload map[string]any // full event payload
    RawData string         // optional raw original event
}
```

### Decode

```go
func (e *StoredEvent) Decode() (any, error)
```

Unmarshals the stored payload into the concrete generated event struct for its class
(e.g. `*events.Authentication` for class_uid 3002), dispatching via the ocsf-schema-go
class-UID registry.

```go
stored, _ := l.QueryByClassUID(ctx, events.ClassUIDAuthentication)
decoded, _ := stored[0].Decode()
if auth, ok := decoded.(*events.Authentication); ok {
    fmt.Println(auth.User.Name)
}
```

### TimeAsTime

```go
func (e *StoredEvent) TimeAsTime() time.Time
```

Converts the OCSF epoch millisecond timestamp to `time.Time`.

## Functions

### ParsePayload

```go
func ParsePayload(data []byte) (map[string]any, error)
```

Parses a JSON payload into a generic map for storage.

### CalculateTypeUID

```go
func CalculateTypeUID(classUID, activityID int) int
```

Computes `type_uid` using the OCSF formula `class_uid * 100 + activity_id`.

### ParseTypeUID

```go
func ParseTypeUID(typeUID int) (classUID, activityID int)
```

Extracts `class_uid` and `activity_id` from a `type_uid`.

## Classification constants

Use the generated constants and caption maps from ocsf-schema-go:

```go
events.ClassUIDAuthentication // 3002
events.CategoryUIDIAM         // 3
events.SeverityIDHigh         // 4
events.StatusIDFailure        // 2

events.ClassNames[3002]       // "authentication"
events.ClassCaptions[3002]    // "Authentication"
events.CategoryCaptions[3]    // "Identity & Access Management"
events.SeverityIDCaptions[4]  // "High"
```
