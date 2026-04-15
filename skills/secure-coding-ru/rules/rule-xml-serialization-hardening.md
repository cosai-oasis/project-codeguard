---
description: Упрочнение XML-парсеров и безопасная десериализация (XXE, entity expansion, polymorphic-type-атаки)
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

# Упрочнение XML и сериализации

## Почему это отдельное правило

Здесь живут два класса уязвимостей с общим источником — пейлоад, которым управляет атакующий, попадает в парсер, который по умолчанию сделает больше, чем задумало приложение:

- **XXE / entity expansion**: XML-парсер резолвит внешние сущности, загружая ресурсы по выбору атакующего либо взрывая крошечный пейлоад в гигабайты в памяти.
- **Небезопасная нативная десериализация**: рантайм языка восстанавливает граф объектов из байтов, по пути вызывая конструкторы и гаджет-цепочки.

Оба — обычно конфигурация, отключённая по умолчанию. Оба требуют осведомлённости о парсере / фреймворке, а не только валидации ввода.

## Упрочнение XML-парсера

### Дефолты

Отключайте DTD полностью. Отказывайтесь от `DOCTYPE`-объявлений до парсинга. Если юз-кейс требует DTD (редко) — отключайте резолвинг внешних сущностей.

Плюс:

- Валидируйте против локально-доверенной XSD. Никогда не доверяйте `SYSTEM` / `PUBLIC` ссылкам в документе.
- Ставьте явные лимиты — общий размер, глубина элементов, счётчик entity-expansion.
- Никакого сетевого доступа во время парсинга. Резолвер должен возвращать `null` или бросать исключение.

### Java

В Java-парсерах XXE **включён по умолчанию**, в нескольких API. Безопасный стартовый шаблон:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

String feature = "http://apache.org/xml/features/disallow-doctype-decl";
try {
    dbf.setFeature(feature, true);
} catch (ParserConfigurationException e) {
    log.warn("Парсер не поддерживает {} — продолжаем упрочнение", feature);
}

dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

Если DTD действительно нельзя отключить — отключайте каждую фичу резолвинга сущностей:

```java
String[] toDisable = {
    "http://xml.org/sax/features/external-general-entities",
    "http://xml.org/sax/features/external-parameter-entities",
    "http://apache.org/xml/features/nonvalidating/load-external-dtd",
};
for (String f : toDisable) {
    try { dbf.setFeature(f, false); } catch (Exception e) { /* лог */ }
}
```

Для `SAXParserFactory` имена фич те же. Для `TransformerFactory` — см. раздел XSLT ниже.

### .NET

```csharp
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver  = null,
    MaxCharactersFromEntities = 0,
};
using var reader = XmlReader.Create(stream, settings);
```

Дефолты `XmlDocument` в свежих версиях .NET улучшились, но явный `XmlResolver = null` остаётся самой безопасной позицией.

### Python

Используйте `defusedxml` как drop-in-замену:

```python
from defusedxml import ElementTree as ET
tree = ET.parse('file.xml')
```

Либо явно конфигурируйте `lxml`:

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

Стандартный `xml.etree.ElementTree` имеет митигации с Python 3.7.1, но всё равно предпочитайте `defusedxml` — пакет существует именно потому, что дефолтные выборы долго были неверны.

### Go, Ruby, PHP

- **Go**: пакет `encoding/xml` не резолвит внешние сущности. Это безопасный дефолт. Следите за entity-expansion через `&ampamp;`-цепочки, если используете сторонний парсер.
- **Ruby**: у `REXML` была история с XXE; предпочитайте `Nokogiri` с `NONET | NOENT = false`.
- **PHP**: `LIBXML_NOENT` — только когда явно нужна подстановка сущностей (бывает редко). По умолчанию не ставьте. Для DOM: `libxml_disable_entity_loader(true)` там, где ещё доступен; в современных PHP entity loading отключён по умолчанию, но проверяйте.

## XSLT / Transformer-ы

Трансформеры умеют тянуть удалённые стили и DTD. Запирайте:

```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

Пустая строка означает «никаких протоколов не разрешено», это и есть задуманный lockdown.

## Безопасная десериализация

**Короткое правило**: никогда не десериализуйте недоверенные нативные бинарные форматы. Предпочитайте JSON (или Protobuf / Cap'n Proto со схемой) и валидируйте явно.

### Почему

Нативная десериализация с точки зрения рантайма запускает произвольный код — конструкторы, callbacks десериализации, property-setter-ы. «Гаджет-цепочки» в с виду безобидных классах на classpath достаточно, чтобы получить RCE.

### Языковые ориентиры

- **PHP**: никогда не вызывайте `unserialize()` на недоверенном вводе. Используйте `json_decode()`.
- **Python**: никакого `pickle` на недоверенных данных. Для YAML — `yaml.safe_load`; `yaml.load` исполняет произвольный Python по дизайну.
- **Java**:
  - Избегайте `ObjectInputStream` / `readObject` на недоверенных данных.
  - Если неизбежно — наследуйте `ObjectInputStream` и перекройте `resolveClass`, отклоняя всё, кроме явного allow-list.
  - Jackson: никогда не включайте default typing (`activateDefaultTyping`). Если нужна полиморфность — `@JsonTypeInfo` с `JsonTypeInfo.Id.NAME` и `@JsonSubTypes`, ограничивающий допустимые типы.
  - XStream: агрессивно конфигурируйте `allow*` type-filter-ы; дефолты XStream исторически небезопасны.
- **.NET**:
  - Избегайте `BinaryFormatter` полностью (deprecated с .NET 5, дальше удалён в 8).
  - `NetDataContractSerializer` и `SoapFormatter` — те же проблемы.
  - Предпочитайте `System.Text.Json` или `DataContractSerializer` с known-type-ами.
  - Json.NET (Newtonsoft): избегайте `TypeNameHandling.All / Auto` — используйте `None` или ограничьте `SerializationBinder`.
- **Node.js**: `JSON.parse` безопасен. `node-serialize` — нет (`unserialize()` исполнял функции); это известный RCE-источник. Не используйте.
- **Ruby**: `Marshal.load` на недоверенных данных исполняет код; только для доверенного ввода. Для YAML — `YAML.safe_load`.

### Универсальные правила

- Ставьте лимиты размера и структуры **до** парсинга. Двухстрочный YAML с миллиардной вложенностью всё ещё беда.
- Подписывайте сериализованные пейлоады, где это позволяет протокол. Проверяйте подпись до парсинга.
- Логируйте и алёртьте на сбои десериализации — они часто первый сигнал попытки эксплуатации.

## Чек-лист реализации

- Все точки входа XML отключают DTD (или как минимум резолвинг внешних сущностей).
- Включена secure-processing-фича; `XIncludeAware` и entity-expansion off.
- XSLT / Transformer-фабрики запрещают внешние ресурсы.
- Никакой нативной десериализации недоверенного ввода. JSON (со schema-валидацией) или schema-based бинарный формат — дефолт.
- Jackson / XStream / .NET-сериализаторы сконфигурированы с type allow-list.
- Лимиты размера и глубины выставлены для каждого парсера.
- Сбои десериализации логируются и достойны алерта.

## План тестирования

- Прогоняйте классические XXE-пейлоады (`<!DOCTYPE foo SYSTEM ...>`, billion laughs, варианты parameter-entity) по каждому XML-эндпоинту.
- Фаззьте битыми YAML / pickled-пейлоадами на границе.
- Юнит-тесты, что конфиг Jackson / XStream отвергает known-bad тип.
- Держите библиотеки свежими (`rule-supply-chain-dependencies.md`).
