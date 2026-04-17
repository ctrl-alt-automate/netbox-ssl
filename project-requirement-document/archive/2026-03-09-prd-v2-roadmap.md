# **Product Requirements Document v2: NetBox SSL Plugin — Roadmap & Volgende Fasen**

Project Code: JANUS
Versie: 2.0 (Roadmap Document)
Status: Draft — Ter Bespreking
Voorganger: PRD v1.1 (MVP, volledig geïmplementeerd als v0.5.0)
Doelgroep: Backend Developers, Plugin Maintainers, Infrastructure Teams

---

## **1. Context & Uitgangspunten**

### 1.1 Wat is er bereikt (v0.1–v0.5)

De MVP en eerste iteraties zijn volledig geïmplementeerd. De plugin biedt op dit moment:

- Certificate model met volledige X.509 attributen, ACME tracking en chain validatie
- CertificateAssignment met GenericForeignKey (Device, VM, Service)
- CertificateAuthority met auto-detectie op basis van issuer patterns
- CertificateSigningRequest tracking
- CompliancePolicy & ComplianceCheck framework (10 policy types)
- Smart Paste Import met private key rejection en renewal detectie
- Janus Renewal workflow (Replace & Archive, atomair)
- Bulk import via PEM, CSV en JSON met preview workflow
- Multi-format export (CSV, JSON, YAML, PEM)
- Chain validation (signatuur, geldigheid, self-signed detectie)
- REST API met 15+ custom actions en 6 ViewSets
- GraphQL schema
- Dashboard widget (Expired, Critical, Warning, Orphan)
- Email notificaties voor verlopen certificaten
- ACME auto-detectie (15+ providers)
- CI/CD pipeline voor NetBox 4.4 en 4.5
- Template extensions op Device, VM en Service detail pagina's

### 1.2 Onveranderde Principes

De volgende architecturale beslissingen uit PRD v1 blijven ongewijzigd:

| Principe | Toelichting |
|:---|:---|
| **Passieve Administratie** | De plugin blijft een inventaris- en monitoringsysteem. Geen actieve deployment, geen ACME-bot die certificaten uitrolt. |
| **Geen Private Key Opslag** | Er worden geen private keys opgeslagen. Het `private_key_location` veld blijft een "breadcrumb" — een hint, geen secret. |
| **Geen Honey Pot** | De database bevat nooit bruikbaar cryptografisch materiaal. Dit is een fundamentele veiligheidsgarantie. |
| **Replace & Archive** | Renewal gebeurt altijd via nieuw object + archivering. Nooit een UPDATE op een bestaand certificaat. Audit trail is heilig. |
| **N en N-1 Versie Support** | Primair NetBox 4.5.x, secundair 4.4.x. Oudere versies worden niet ondersteund. |

### 1.3 Nieuwe Richtlijnen voor v2

- **Incrementele releases** — Elke release heeft een duidelijk thema en is zelfstandig bruikbaar.
- **Backward compatible** — Migraties mogen bestaande data niet breken. Nieuwe velden krijgen defaults.
- **API-first** — Elke nieuwe feature moet een REST API endpoint hebben voordat de UI gebouwd wordt.
- **Configureerbaar** — Features worden aangestuurd via plugin settings, niet hardcoded.

---

## **2. Release Roadmap Overzicht**

| Release | Thema | Focus |
|:---|:---|:---|
| **v0.6** | Observability & Webhooks | Event-driven notificaties, integratie met externe systemen |
| **v0.7** | Certificate Landscape | Visueel inzicht, analytics, rapportages |
| **v0.8** | Workflow Automation & External Sources | Lifecycle management, scheduled jobs, externe bronkoppelingen |
| **v0.9** | Enterprise & Hardening | RBAC verfijning, performance, import/export uitbreiding |
| **v1.0** | General Availability | Stabiliteit, documentatie, community-ready |

---

## **3. Release v0.6 — Observability & Webhooks**

### 3.1 Doel

De plugin moet "luidruchtig" zijn wanneer er actie nodig is. Teams die niet dagelijks in NetBox kijken, moeten toch gewaarschuwd worden via hun bestaande tooling (Slack, Teams, PagerDuty, etc.).

### 3.2 Features

#### 3.2.1 NetBox Event Rules Integratie

**Beschrijving:** Certificaat-events (aanmaken, verwijderen, status wijziging, expiry threshold) moeten NetBox Event Rules triggeren. Dit maakt het mogelijk om via de standaard NetBox webhook/script engine notificaties te sturen.

**Requirements:**

- Certificate model events (create, update, delete) triggeren NetBox's ingebouwde Event Rules
- Custom events voor: `certificate_expired`, `certificate_expiring_soon`, `certificate_renewed`, `certificate_revoked`
- Event payload bevat: certificate ID, common_name, days_remaining, status, assigned objects
- Documentatie met voorbeelden voor Slack, Teams en PagerDuty webhook configuratie

**Besluit:** We bouwen geen eigen notificatie-integraties. We leunen op NetBox's Event Rules systeem, zodat gebruikers hun eigen endpoints configureren. Dit houdt de plugin simpel en flexibel.

#### 3.2.2 Scheduled Expiry Scanning

**Beschrijving:** Een NetBox scheduled job die periodiek alle actieve certificaten scant en events genereert voor certificaten die een drempelwaarde naderen of passeren.

**Requirements:**

- NetBox Script/Job dat als scheduled task kan draaien
- Configureerbare thresholds via plugin settings (standaard: 14/30/60/90 dagen)
- Genereert events die door Event Rules opgepakt worden
- Idempotent: dezelfde scan twee keer draaien levert geen dubbele notificaties
- Log output voor audit doeleinden
- Optie om per-tenant te filteren

#### 3.2.3 Certificate Changelog Verrijking

**Beschrijving:** Uitgebreidere changelog entries zodat wijzigingen in certificaatstatus, assignments en renewals duidelijk terug te vinden zijn.

**Requirements:**

- Changelog entries bij: status wijzigingen, assignment toevoegen/verwijderen, renewal events
- Duidelijke "before → after" weergave bij status transities
- Link naar gerelateerde objecten in changelog (bijv. "Replaced by Certificate #123")

---

## **4. Release v0.7 — Certificate Landscape**

### 4.1 Doel

Teams moeten in één oogopslag hun certificaatlandschap begrijpen. Niet alleen "wat verloopt binnenkort?" maar ook "hoe ziet ons totaalbeeld eruit?"

### 4.2 Features

#### 4.2.1 Certificate Analytics Dashboard

**Beschrijving:** Een uitgebreide dashboard pagina (los van de homepage widget) met statistieken en grafieken over het certificaatlandschap.

**Requirements:**

- Overzichtspagina bereikbaar via het navigatiemenu
- Statistieken:
  - Totaal actieve certificaten
  - Verdeling per status (Active, Expired, Replaced, Revoked)
  - Verdeling per CA (issuer)
  - Verdeling per algoritme (RSA vs ECDSA vs Ed25519)
  - Gemiddelde resterende geldigheidsduur
  - Certificaten zonder assignments (orphans)
  - ACME vs non-ACME verdeling
- Tijdlijn: "Expiry Forecast" — hoeveel certificaten verlopen per maand in de komende 12 maanden
- Filterbaar per tenant

**Technisch:** Server-side aggregatie via Django ORM. Geen zware client-side rendering. Grafieken via NetBox's bestaande charting aanpak of lichtgewicht SVG.

#### 4.2.2 Compliance Rapportage

**Beschrijving:** Een overzicht van compliance-resultaten dat als rapport geëxporteerd kan worden.

**Requirements:**

- Compliance score per certificaat (percentage passed checks)
- Compliance overzicht per tenant
- Compliance trend over tijd (opslaan van historische check results)
- Export als CSV of JSON voor externe rapportage tools
- API endpoint: `GET /api/plugins/netbox-ssl/compliance-report/`

#### 4.2.3 Certificate Map (Topology View)

**Beschrijving:** Een visuele weergave van welke certificaten waar gekoppeld zijn, gegroepeerd per device/cluster.

**Requirements:**

- Boomstructuur: Tenant → Device/VM → Service → Certificate(s)
- Kleurcodering op basis van expiry status (groen/oranje/rood)
- Klikbaar: navigeer door naar detail pagina's
- Filterbaar op tenant, status, CA

**Besluit:** Dit wordt een read-only view. Geen drag-and-drop assignment. De bestaande assignment workflow via formulieren blijft de primaire manier om koppelingen te beheren.

---

## **5. Release v0.8 — Workflow Automation**

### 5.1 Doel

Repetitieve taken automatiseren zonder de passieve filosofie te verlaten. De plugin helpt bij het *administreren* van de lifecycle, niet bij het *uitvoeren* ervan.

### 5.2 Features

#### 5.2.1 Renewal Reminders & Runbooks

**Beschrijving:** Geautomatiseerde herinneringen die niet alleen waarschuwen maar ook context bieden: "Dit certificaat verloopt over 30 dagen. Hier is wat je moet doen."

**Requirements:**

- Per CertificateAuthority configureerbare renewal instructies (Markdown tekstveld)
- Per Certificate optioneel een custom renewal note
- Bij expiry events wordt de relevante renewal instructie meegestuurd in de event payload
- UI: Op de certificate detail pagina een "Renewal Guide" sectie die de CA-instructies toont

#### 5.2.2 Bulk Operations Uitbreiding

**Beschrijving:** Uitbreiding van bulk acties voor efficiënt beheer van grote certificaatbestanden.

**Requirements:**

- Bulk status wijziging (bijv. selecteer 20 certificaten → markeer als Revoked)
- Bulk assignment: wijs meerdere certificaten toe aan dezelfde service/device
- Bulk compliance check: draai alle policies tegen een selectie certificaten
- Bulk chain validation: valideer chains voor een selectie
- Alle bulk operaties beschikbaar via zowel UI als API

#### 5.2.3 Certificate Lifecycle Tracking

**Beschrijving:** Volg de volledige levenscyclus van een certificaat van aanvraag tot archivering.

**Requirements:**

- Lifecycle states: Requested (CSR) → Issued → Active → Expiring → Expired/Renewed/Revoked
- Automatische state transitions op basis van valid_from/valid_to
- Timeline view op certificate detail pagina: wanneer is het aangemaakt, geïmporteerd, gerenewed, etc.
- Koppeling CSR → Certificate versterken: bij import checken of er een matching CSR bestaat
- Lifecycle duration statistieken (gemiddelde levensduur per CA, per type)

#### 5.2.4 Auto-Archive Policy

**Beschrijving:** Automatisch verlopen certificaten archiveren na een configureerbare periode.

**Requirements:**

- Plugin setting: `auto_archive_after_days` (standaard: 90 dagen na expiry)
- Scheduled job die verlopen certificaten met status "Expired" omzet naar "Archived" (nieuwe status)
- Archived certificaten worden niet getoond in standaard lijsten (filterbaar)
- Nooit automatisch verwijderen — alleen status wijzigen
- Handmatige override mogelijk: certificaat kan "vastgepind" worden om auto-archive te voorkomen

#### 5.2.5 External Source Framework

**Beschrijving:** Een generiek framework waarmee externe certificaatbeheersystemen als read-only bron gekoppeld kunnen worden aan NetBox SSL. De plugin haalt periodiek certificaat-metadata op en synchroniseert deze naar de lokale inventaris.

**Filosofie:** Dit is de "passieve import" tegenhanger van handmatige Smart Paste. Waar Smart Paste geschikt is voor incidentele imports, dekt het External Source framework de structurele sync met systemen die elders het productieproces van certificaten aansturen. NetBox SSL blijft het administratiesysteem — de externe bron is het productiesysteem.

**Requirements — Abstractie (ExternalSource model):**

- Nieuw model `ExternalSource` met velden:
  - `name` (String) — Herkenbare naam (bijv. "Productie Lemur", "DigiCert CertCentral")
  - `source_type` (ChoiceField) — Type backend (Lemur, DigiCert, Venafi, Generic REST)
  - `base_url` (URLField) — API endpoint van de externe bron
  - `auth_method` (ChoiceField) — Bearer Token, API Key, OAuth2 Client Credentials
  - `auth_credentials_reference` (String) — Verwijzing naar credential opslag (bijv. NetBox Secrets, environment variable naam). **Geen plaintext credentials in de database.**
  - `sync_interval_minutes` (Integer) — Hoe vaak synchroniseren (standaard: 360)
  - `enabled` (Boolean) — Aan/uit schakelaar
  - `tenant` (ForeignKey, optioneel) — Geïmporteerde certificaten krijgen deze tenant
  - `last_sync_at` (DateTime) — Tijdstip van laatste succesvolle sync
  - `last_sync_status` (ChoiceField) — Success, Partial, Failed
  - `last_sync_message` (TextField) — Foutmelding of samenvatting
  - `certificate_count` (Integer) — Aantal certificaten van deze bron
  - `tags` (TagField) — Automatisch toegevoegd aan geïmporteerde certificaten
- Elk geïmporteerd certificaat krijgt een `external_source` ForeignKey en een `external_id` (String) voor deduplicatie
- CRUD views en API endpoints voor ExternalSource beheer

**Requirements — Sync Engine:**

- Scheduled NetBox Job dat alle actieve ExternalSources pollt
- Per sync-run:
  1. Ophalen van certificaat-metadata via de bron-specifieke adapter
  2. Matching op `external_source` + `external_id` (update) of `fingerprint_sha256` (deduplicatie)
  3. Nieuwe certificaten → aanmaken met status Active
  4. Gewijzigde certificaten → Janus Renewal patroon volgen als serial_number verschilt (nieuw object, assignments kopiëren, oud → Replaced). Metadata-updates (bijv. gewijzigde tags) → in-place update
  5. Verwijderde certificaten in de bron → **niet** automatisch verwijderen in NetBox SSL, maar markeren met een `source_removed` flag zodat de beheerder kan beslissen
- Dry-run modus: toon wat er zou veranderen zonder daadwerkelijk te synchroniseren
- Sync log per run (aantal nieuw, bijgewerkt, ongewijzigd, verwijderd-in-bron, fouten)
- API endpoint: `POST /api/plugins/netbox-ssl/external-sources/{id}/sync/` voor handmatige trigger

**Requirements — Veiligheid:**

- Alleen publieke certificaat-metadata ophalen. Nooit private keys opvragen, zelfs als de bron-API het ondersteunt
- Adapter implementaties moeten expliciet de op te halen velden definiëren (allowlist, geen blocklist)
- Credentials worden nooit gelogd of getoond in de UI (gemaskeerd)
- TLS verificatie verplicht bij communicatie met externe bronnen (insecure optie alleen via expliciete setting)

**Requirements — Adapter Interface:**

Een Python abstract base class `ExternalSourceAdapter` met de volgende interface:

- `test_connection() → bool` — Verbindingstest
- `fetch_certificates(since: datetime | None) → list[ParsedCertificate]` — Ophalen van certificaten, optioneel incrementeel
- `get_certificate_detail(external_id: str) → ParsedCertificate` — Enkel certificaat ophalen
- `map_to_parsed_certificate(raw_data: dict) → ParsedCertificate` — Vertaling van bron-specifiek formaat naar ons datamodel

Adapters worden geregistreerd via een registry pattern, vergelijkbaar met NetBox's eigen plugin systeem.

**Meegeleverde Adapters (initieel):**

| Adapter | Bron | Bijzonderheden |
|:---|:---|:---|
| `LemurAdapter` | Netflix Lemur | JWT authenticatie, `GET /certificates` endpoint, filtert private key velden uit response |
| `GenericRESTAdapter` | Willekeurige REST API | Configureerbare field mapping (JSON path expressies voor CN, SANs, issuer, validity, etc.) |

**Toekomstige Adapters (post-v0.8, community of zelf):**

| Adapter | Bron | Status |
|:---|:---|:---|
| `DigiCertAdapter` | DigiCert CertCentral | Kandidaat voor v0.9 of community bijdrage |
| `VenafiAdapter` | Venafi Trust Protection Platform | Kandidaat voor v0.9 of community bijdrage |
| `AWSACMAdapter` | AWS Certificate Manager | Read-only via `list-certificates` / `describe-certificate` API |
| `AzureKeyVaultAdapter` | Azure Key Vault (Certificates) | Read-only, alleen publieke metadata |
| `ScanResultAdapter` | Nmap/sslyze output (JSON/XML) | Passieve import van scan-resultaten, geen actieve scanning |

**Besluit:** Adapters voor commerciële platforms (DigiCert, Venafi) worden niet in de eerste release meegeleverd. De `GenericRESTAdapter` met configureerbare field mapping dekt veel use cases af. Community bijdragen voor specifieke adapters worden aangemoedigd via een gedocumenteerd adapter development guide.

**UI:**

- ExternalSource list view met sync status indicators (groen/oranje/rood)
- ExternalSource detail view met: configuratie, laatste sync log, gekoppelde certificaten
- "Sync Now" knop voor handmatige trigger
- Certificaat list view: filterbaar op `external_source`
- Certificaat detail view: badge/label die aangeeft uit welke externe bron het certificaat afkomstig is

---

## **6. Release v0.9 — Enterprise & Hardening**

### 6.1 Doel

Klaar maken voor gebruik in grotere organisaties met strikte toegangscontrole en hoge volumes.

### 6.2 Features

#### 6.2.1 Granulaire Permissies

**Beschrijving:** Fijnmaziger toegangscontrole bovenop NetBox's standaard permission model.

**Requirements:**

- Object-level permissions via NetBox's ingebouwde ObjectPermission model
- Tenant-scoped views: gebruikers zien alleen certificaten van hun eigen tenant(s)
- Separate permissies voor: import, renewal, bulk operaties, compliance beheer
- Read-only mode voor audit gebruikers (kunnen alles zien, niets wijzigen)

#### 6.2.2 Performance Optimalisatie

**Beschrijving:** De plugin moet performant blijven bij grote aantallen certificaten (10.000+).

**Requirements:**

- Database indexen op veelgebruikte filtervelden (valid_to, status, tenant, issuer)
- Prefetch/select_related optimalisatie op list views en API endpoints
- Paginatie op alle list endpoints (API en UI)
- Lazy loading van zware velden (pem_content, issuer_chain) in list views
- Benchmark tests: list view < 500ms bij 10.000 certificaten

#### 6.2.3 Import/Export Uitbreiding

**Beschrijving:** Ondersteuning voor meer formaten en bronnen.

**Requirements:**

- Import van PKCS#7 (.p7b) bestanden — extractie van certificaten uit chain bundles
- Import vanuit DER/binary format (naast PEM)
- Export met volledige assignment data (welk certificaat zit op welk device/service)
- Scheduled export: periodiek een rapport genereren en opslaan (bijv. voor compliance audits)
- API endpoint voor "diff" tussen twee exports (wat is er veranderd sinds vorige week?)

#### 6.2.4 Custom Fields & Tags Verdieping

**Beschrijving:** Betere integratie met NetBox's custom fields en tagging systeem.

**Requirements:**

- Custom fields ondersteuning op alle plugin models (niet alleen Certificate)
- Tag-based filtering in alle views en API endpoints
- Mogelijkheid om compliance policies te koppelen aan tags (bijv. "alle certificaten met tag 'production' moeten minimaal 4096-bit key hebben")
- Export bevat custom field waarden

---

## **7. Release v1.0 — General Availability**

### 7.1 Doel

De plugin is stabiel, goed gedocumenteerd en klaar voor brede adoptie door de NetBox community.

### 7.2 Features

#### 7.2.1 Documentatie

**Requirements:**

- Volledige gebruikershandleiding (installatie, configuratie, workflows)
- API documentatie met voorbeelden (curl, Python requests)
- Administrator guide (plugin settings, scheduled jobs, Event Rules setup)
- Contribution guide voor externe ontwikkelaars
- Publicatie op Read the Docs of vergelijkbaar platform

#### 7.2.2 Migration & Upgrade Tooling

**Requirements:**

- Geautomatiseerde data migratie bij plugin upgrades
- Rollback instructies bij elke release
- Health check commando: `manage.py check --tag netbox_ssl` uitbreiden met database integriteit checks
- Versie compatibility matrix in documentatie

#### 7.2.3 Community & Packaging

**Requirements:**

- Publicatie op PyPI (`pip install netbox-ssl`)
- Nette README met badges (CI status, PyPI versie, NetBox compatibility)
- Issue templates op GitHub (bug report, feature request)
- CHANGELOG.md met alle releases
- Semantic versioning beleid documenteren

#### 7.2.4 Stabiliteit & Testing

**Requirements:**

- Test coverage > 80% op alle modules
- E2E tests voor alle primaire workflows (import, renewal, bulk, compliance)
- Load tests voor API endpoints bij hoog volume
- Geen bekende data-verlies scenario's
- Security review: geen injection mogelijkheden in import/parse flows

---

## **8. Toekomstige Verkenningen (Post v1.0)**

De volgende ideeën vallen buiten de v1.0 scope maar zijn het verkennen waard voor een eventuele v1.x of v2.0:

| Idee | Beschrijving | Passieve Filosofie? |
|:---|:---|:---|
| **Git-backed Audit Trail** | Exporteer certificaat state naar een Git repository voor versiebeheer buiten NetBox | ✅ Ja — read-only export |
| **Multi-Instance Sync** | Synchronisatie van certificaatdata tussen meerdere NetBox instanties | ⚠️ Complex — vereist conflict resolution |
| **Vault Integratie (Read-Only)** | Haal `private_key_location` metadata op uit HashiCorp Vault (geen keys, alleen paden) | ✅ Ja — alleen metadata, geen secrets |
| **CT Log Monitoring** | Gebruik Certificate Transparency logs om te detecteren of er certificaten zijn uitgegeven voor jouw domeinen | ✅ Ja — passieve monitoring van publieke data |
| **SLA Tracking** | Definieer SLA's per tenant/CA: "Renewal moet binnen X dagen na melding afgehandeld zijn" | ✅ Ja — administratief |
| **Community Adapters** | Extra External Source adapters (DigiCert, Venafi, AWS ACM, Azure Key Vault) via community bijdragen | ✅ Ja — read-only sync |

---

## **9. Technische Overwegingen**

### 9.1 Database Migraties

Elke release moet:
- Reversible migraties bevatten (RunSQL met reverse_sql)
- Nieuwe velden altijd met `default` of `null=True`
- Data migraties los van schema migraties
- Getest tegen zowel NetBox 4.4 als 4.5

### 9.2 API Versioning

- Huidige API endpoints blijven backward compatible
- Breaking changes (indien nodig) worden geïntroduceerd onder een versioned prefix
- Deprecation warnings minimaal één release voor verwijdering

### 9.3 Plugin Settings Uitbreiding

Verwachte nieuwe settings per release:

```python
# v0.6
'expiry_scan_thresholds': [14, 30, 60, 90],  # dagen
'event_deduplication_hours': 24,

# v0.8
'auto_archive_after_days': 90,
'auto_archive_enabled': False,
'lifecycle_tracking_enabled': True,
'external_source_sync_enabled': True,
'external_source_default_interval': 360,       # minuten
'external_source_tls_verify': True,
'external_source_never_fetch_keys': True,       # safety lock, niet configureerbaar via UI

# v0.9
'performance_prefetch_limit': 1000,
'lazy_load_pem_content': True,
```

---

## **10. Succescriteria**

| Criterium | Meetbaar |
|:---|:---|
| Plugin is installeerbaar via `pip install` | PyPI publicatie |
| Geen data verlies bij upgrade van v0.5 → v1.0 | Migratie tests |
| API response time < 500ms bij 10.000 certificaten | Load tests |
| Test coverage > 80% | Coverage rapport |
| Documentatie beschikbaar voor alle features | Review checklist |
| Community adoptie: 10+ GitHub stars binnen 3 maanden na v1.0 | GitHub metrics |
| Nul security vulnerabilities in import/parse flows | Security review |

---

*Dit document is een levend document en wordt bijgewerkt naarmate releases worden opgeleverd.*
