---
description: XML parser hardening and safe deserialization (XXE, entity expansion, polymorphic type attacks)
languages:
  - c
  - go
  - java
  - php
  - python
  - ruby
  - xml
alwaysApply: false
rule_id: rule-xml-serialization-hardening
---

# XML & Serialization Hardening

## Why this is its own rule

Two vulnerability classes live here that share an origin — an attacker-controlled payload is fed to a parser that will, by default, do more than the application intended:

- **XXE / entity expansion**: the XML parser resolves external entities, loading attacker-chosen resources or exploding a tiny payload into gigabytes in memory.
- **Unsafe native deserialization**: the language runtime reconstructs object graphs from bytes, invoking constructors and gadget chains along the way.

Both are usually an off-by-default configuration. Both require parser / framework awareness, not just input validation.

## XML parser hardening

### Defaults

Disable DTDs entirely. Refuse `DOCTYPE` declarations before parsing. If the use case requires DTDs (rare), disable external entity resolution.

Also:

- Validate against a locally-trusted XSD. Never trust `SYSTEM` / `PUBLIC` references in the document.
- Set explicit caps — total size, element depth, entity expansion count.
- No network access during parsing. Force the resolver to return `null` or throw.

### Java

Java parsers have XXE **enabled by default**, across multiple APIs. The safe starting pattern:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

String feature = "http://apache.org/xml/features/disallow-doctype-decl";
try {
    dbf.setFeature(feature, true);
} catch (ParserConfigurationException e) {
    log.warn("Parser does not support {} — continuing hardening", feature);
}

dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

If DTDs truly cannot be disabled, also disable each entity-resolution feature:

```java
String[] toDisable = {
    "http://xml.org/sax/features/external-general-entities",
    "http://xml.org/sax/features/external-parameter-entities",
    "http://apache.org/xml/features/nonvalidating/load-external-dtd",
};
for (String f : toDisable) {
    try { dbf.setFeature(f, false); } catch (Exception e) { /* log */ }
}
```

For `SAXParserFactory`, the same feature names apply. For `TransformerFactory`, see the XSLT section below.

### .NET

```csharp
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver  = null,
    MaxCharactersFromEntities = 0,
};
using var reader = XmlReader.Create(stream, settings);
```

`XmlDocument` defaults changed for the better in recent .NET versions, but explicitly setting `XmlResolver = null` is still the safest posture.

### Python

Use `defusedxml` as a drop-in replacement:

```python
from defusedxml import ElementTree as ET
tree = ET.parse('file.xml')
```

Or configure `lxml` explicitly:

```python
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    huge_tree=False,
    dtd_validation=False,
    load_dtd=False,
)
tree = etree.parse('file.xml', parser)
```

Standard-library `xml.etree.ElementTree` has mitigations since Python 3.7.1 but still prefer `defusedxml` — the package exists exactly because the default choices were wrong for a long time.

### Go, Ruby, PHP

- **Go**: the `encoding/xml` package does not resolve external entities. This is a safe default. Be aware of entity expansion via `&ampamp;` chains if you use a third-party parser.
- **Ruby**: `REXML` had historical XXE issues; prefer `Nokogiri` with `NONET | NOENT = false`.
- **PHP**: use `LIBXML_NOENT` only when you explicitly need entity substitution (which is rarely). Default to not setting it. For DOM: `libxml_disable_entity_loader(true)` where still available; on modern PHP, entity loading is off by default but verify.

## XSLT / Transformers

Transformers can fetch remote stylesheets and DTDs. Lock them down:

```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

The empty string means "no protocols allowed", which is the intended lockdown.

## Safe deserialization

**The short rule**: never deserialize untrusted native binary formats. Prefer JSON (or Protobuf / Cap'n Proto with a schema) and validate it explicitly.

### Why

Native deserialization runs arbitrary code from the runtime's perspective — constructors, deserialization callbacks, property setters. A "gadget chain" inside an innocuous-looking class on the classpath is enough to achieve remote code execution.

### Language-specific guidance

- **PHP**: never call `unserialize()` on untrusted input. Use `json_decode()`.
- **Python**: no `pickle` on untrusted data. For YAML, use `yaml.safe_load` — `yaml.load` executes arbitrary Python by design.
- **Java**:
  - Avoid `ObjectInputStream` / `readObject` on untrusted data.
  - If unavoidable, subclass `ObjectInputStream` and override `resolveClass` to reject everything except an explicit allow-list.
  - Jackson: never enable default typing (`activateDefaultTyping`). If polymorphism is needed, use `@JsonTypeInfo` with `JsonTypeInfo.Id.NAME` and `@JsonSubTypes` to constrain the allowed types.
  - XStream: configure `allow*` type filters aggressively; XStream's defaults have historically been unsafe.
- **.NET**:
  - Avoid `BinaryFormatter` entirely (deprecated as of .NET 5, removed further in 8).
  - `NetDataContractSerializer` and `SoapFormatter` have the same issues.
  - Prefer `System.Text.Json` or `DataContractSerializer` with known types.
  - Json.NET (Newtonsoft): avoid `TypeNameHandling.All / Auto` — use `None` or constrain with a `SerializationBinder`.
- **Node.js**: `JSON.parse` is safe. `node-serialize` was not (`unserialize()` executed functions) — it is a well-known RCE source. Do not use it.
- **Ruby**: `Marshal.load` on untrusted data executes code; use it only on trusted input. For YAML, `YAML.safe_load`.

### Universal rules

- Enforce size and structure limits **before** parsing. A 2-line YAML file containing billion-deep nesting is still trouble.
- Sign serialized payloads where the protocol permits. Verify the signature before parsing.
- Log and alert on deserialization failures — they are frequently the first signal of an exploitation attempt.

## Implementation checklist

- All XML entry points disable DTDs (or at minimum disable external entity resolution).
- Secure-processing feature is set; `XIncludeAware` and entity expansion are off.
- XSLT / Transformer factories deny external resources.
- No native deserialization of untrusted input. JSON (with schema validation) or a schema-based binary format is the default.
- Jackson / XStream / .NET serializers configured with type allow-lists.
- Size and depth caps set for every parser.
- Deserialization failures are logged and alert-worthy.

## Test plan

- Fire classic XXE payloads (`<!DOCTYPE foo SYSTEM ...>`, billion laughs, parameter entity variants) against every XML-accepting endpoint.
- Fuzz with malformed YAML / pickled payloads on the boundary.
- Unit tests that a Jackson / XStream configuration rejects a known-bad type.
- Keep libraries patched (`rule-supply-chain-dependencies.md`).
