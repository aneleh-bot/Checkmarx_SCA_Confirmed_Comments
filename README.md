# Checkmarx One: SCA Vulnerabilities Report (Confirmed + Authors + Comments) ☆彡

## Description

Python script that scans Checkmarx One projects, retrieves recent scans, filters SCA vulnerabilities with the **Confirmed** state, and for each one queries the SCA/Management of Risk GraphQL API to extract the author of the confirmation note along with the note itself. If the author is not returned by the API, a CSV exported from the UI can be used as a fallback (offline merge).

This script automatically collects **confirmed SCA vulnerabilities** from **Checkmarx One**, extracting:
- Project name  
- Project ID and scan ID  
- CVE or affected package  
- Severity and state  
- Author who confirmed the vulnerability  
- Comment associated with the confirmation  

The results are exported in **Excel (.xlsx)** and **CSV (.csv)** formats, enabling traceability of **who confirmed each vulnerability** and **what comment was added**, which is useful for audits, metrics, and compliance reports.

---

## Requirements

### Python
- **Python 3.9+** (Python 3.10 or higher recommended)

### Dependencies
Install via `pip`:
```bash
pip install requests pandas openpyxl
```

---

## Configuration

Open the file `sca_confirmed_author_comments.py` and configure the following variables at the top of the script:

```python
AST_API_BASE   = "https://eu.ast.checkmarx.net"     # Checkmarx One AST base URL
SCA_API_BASE   = "https://eu.api-sca.checkmarx.net" # Checkmarx SCA API base URL
CLIENT_ID      = "..."                              # Application Client ID (OAuth)
CLIENT_SECRET  = "..."                              # Application Client Secret (OAuth)
TENANT_NAME    = "..."                              # Customer tenant
SCAN_LOOKBACK_DAYS = 2                              # How many days to look back in scans
```

> **Important:**  
> Adjust the URLs according to your region (US, US2, EU, EU2) and insert valid OAuth 2.0 credentials for your Checkmarx One tenant.

Example:
```python
AST_API_BASE   = "https://eu.ast.checkmarx.net"
SCA_API_BASE   = "https://eu.api-sca.checkmarx.net"
CLIENT_ID      = "abcd1234"
CLIENT_SECRET  = "xyz7890"
TENANT_NAME    = "mytenant"
SCAN_LOOKBACK_DAYS = 7
```

---

## How It Works

1. Authenticate with Checkmarx IAM via Client Credentials (OAuth2).  
2. List all available projects.  
3. For each project, retrieve **scans performed in the last N days** (`SCAN_LOOKBACK_DAYS`).  
4. Collect **confirmed** vulnerabilities of type **SCA**.  
5. Use a **GraphQL query** to retrieve the author and comment of the confirmation action.  
6. Generate a consolidated report in **Excel** and **CSV**.

---

## Output

By default, the report is saved in the current directory as:

```
checkmarx_sca_confirmed.xlsx
checkmarx_sca_confirmed.csv
```

### Main columns:
| Field | Description |
|-------|------------|
| Project Name | Project name in Checkmarx |
| Project Id | Unique project ID |
| Scan Id | Analyzed scan ID |
| Result Id | Result (vulnerability) ID |
| CVE/Package | Package name or CVE |
| Severity | Severity (High, Medium, Low, etc.) |
| State | Current state (Confirmed, To Verify, etc.) |
| Author | User who confirmed |
| Author Source | Data source (GraphQL or CSV Merge) |
| Confirm Note | Comment added during confirmation |

---

## Offline Merge Option (CSV History)

You can enable an **offline merge with local history** to fill in older authors:
```python
HISTORY_CSV = r"C:\temp\risk_history.csv"
```

The script will attempt to correlate results with the provided CSV and fill authors not returned by the API.

Leave empty (`HISTORY_CSV = ""`) to disable this feature.

---

## Execution

In the terminal:
```bash
python sca_confirmed_author_comments.py
```

During execution, the script will display progress logs:
```
Projects found: 12
Project 'api-service': 3 scans since 2025-11-08T00:00:00Z
  Scan 12345: 4 CONFIRMED SCA vulnerabilities
[GQL VARS] scan=12345 proj=abcd mgr=Npm pkg=axios ver=0.21.4 cve=CVE-2023-XXXX
```

---

## Example Output (Excel)

| Project Name | CVE/Package | Severity | Author | Confirm Note |
|---------------|-------------|-----------|----------|----------------|
| api-service | CVE-2023-28432 | High | lele | Confirmed vulnerability due to outdated dependency |
| web-app | CVE-2022-3786 | Medium | devops-team | false positive – accepted risk |

---

## Advanced Features

- **Automatic retries:** the script retries requests in case of timeout or 429/500+ errors.  
- **Full pagination:** retrieves all results from large projects.  
- **Dynamically renewed tokens** for each project.  
- **Offline CSV fallback** to preserve author history.

---

## Code Structure

```
sca_confirmed_author_comments.py
├── Initial configuration (URLs, tokens, parameters)
├── Helper functions (_is_confirmed, parse_pkg, etc.)
├── GraphQL Query – extracts author and comment
├── HistoryIndex class – local CSV merge
├── Pagination functions (projects, scans, results)
├── collect_confirmed_sca() – main collection logic
└── export_report() – generates Excel/CSV
```

---

☆彡

---


# SCA Confirmed Comments ☆彡

Checkmarx One: Relatório de Vulnerabilidades SCA (Confirmadas + Autores + Comentários)

## Descrição

Script em Python que varre os projetos do Checkmarx One, pega os scans recentes, filtra vulnerabilidades SCA com estado Confirmed e, para cada uma, consulta o GraphQL de SCA/Management of Risk para extrair quem foi o autor da nota de confirmação, juntamente com a nota feita. Se o autor não vier pela API, dá pra usar um CSV exportado da UI como fallback (merge offline).

Este script coleta automaticamente **vulnerabilidades SCA confirmadas** do **Checkmarx One**, extraindo:
- Nome do projeto  
- ID do projeto e do scan  
- CVE ou pacote afetado  
- Severidade e estado  
- Autor que confirmou a vulnerabilidade  
- Comentário associado à confirmação  

O resultado é exportado em **Excel (.xlsx)** e **CSV (.csv)**, permitindo rastrear **quem confirmou cada vulnerabilidade** e **qual foi o comentário**, útil para auditorias, métricas e relatórios de conformidade.

## Requisitos

### Python
- **Python 3.9+** (recomendado 3.10 ou superior)

### Dependências
Instale via `pip`:
```bash
pip install requests pandas openpyxl
```

---

## Configuração

Abra o arquivo `sca_confirmed_author_comments.py` e configure as seguintes variáveis no topo do script:

```python
AST_API_BASE   = "https://eu.ast.checkmarx.net"     # URL base do Checkmarx One AST
SCA_API_BASE   = "https://eu.api-sca.checkmarx.net" # URL base do Checkmarx SCA API
CLIENT_ID      = "..."                              # Client ID da aplicação (OAuth)
CLIENT_SECRET  = "..."                              # Client Secret da aplicação (OAuth)
TENANT_NAME    = "..."                              # Tenant do cliente
SCAN_LOOKBACK_DAYS = 2                              # Quantos dias retroceder nas análises
```

> **Importante:**  
> Ajuste as URLs conforme sua região (US, US2, EU, EU2) e insira as credenciais válidas de OAuth 2.0 do seu tenant Checkmarx One.

Exemplo:
```python
AST_API_BASE   = "https://eu.ast.checkmarx.net"
SCA_API_BASE   = "https://eu.api-sca.checkmarx.net"
CLIENT_ID      = "abcd1234"
CLIENT_SECRET  = "xyz7890"
TENANT_NAME    = "mytenant"
SCAN_LOOKBACK_DAYS = 7
```

---

## Funcionamento

1. Autentica no **IAM** do Checkmarx via Client Credentials (OAuth2).  
2. Lista todos os projetos disponíveis.  
3. Para cada projeto, busca **scans realizados nos últimos N dias** (`SCAN_LOOKBACK_DAYS`).  
4. Coleta resultados de vulnerabilidades **confirmadas** e do tipo **SCA**.  
5. Usa uma query **GraphQL** para recuperar autor e comentário da ação de confirmação.  
6. Gera um relatório consolidado em **Excel** e **CSV**.

---

## Saída

Por padrão, o relatório é salvo no diretório atual como:

```
checkmarx_sca_confirmed.xlsx
checkmarx_sca_confirmed.csv
```

### Colunas principais:
| Campo | Descrição |
|-------|------------|
| Project Name | Nome do projeto no Checkmarx |
| Project Id | ID único do projeto |
| Scan Id | ID do scan analisado |
| Result Id | ID do resultado (vulnerabilidade) |
| CVE/Package | Nome do pacote ou CVE |
| Severity | Severidade (High, Medium, Low, etc.) |
| State | Estado atual (Confirmed, To Verify, etc.) |
| Author | Usuário que confirmou |
| Author Source | Origem do dado (GraphQL ou CSV Merge) |
| Confirm Note | Comentário feito na confirmação |

---

## Opção de Merge Offline (Histórico CSV)

Você pode habilitar um **merge com histórico local** para preencher autores antigos:
```python
HISTORY_CSV = r"C:\temp\risk_history.csv"
```

O script tentará cruzar resultados com o CSV informado e preencher autores que não foram retornados pela API.

Deixe vazio (`HISTORY_CSV = ""`) para desabilitar essa função.

---

## Execução

No terminal:
```bash
python sca_confirmed_author_comments.py
```

Durante a execução, o script exibirá logs de progresso:
```
Projetos encontrados: 12
Projeto 'api-service': 3 scans desde 2025-11-08T00:00:00Z
  Scan 12345: 4 vulnerabilidades SCA CONFIRMADAS
[GQL VARS] scan=12345 proj=abcd mgr=Npm pkg=axios ver=0.21.4 cve=CVE-2023-XXXX
```

---

## Exemplo de Resultado (Excel)

| Project Name | CVE/Package | Severity | Author | Confirm Note |
|---------------|-------------|-----------|----------|----------------|
| api-service | CVE-2023-28432 | High | lele | Confirmed vulnerability due to outdated dependency |
| web-app | CVE-2022-3786 | Medium | devops-team | false positive – accepted risk |

---

## Recursos Avançados

- **Retries automáticos:** o script reenvia requisições em caso de timeout ou erro 429/500+.  
- **Paginação completa:** busca todos os resultados de projetos grandes.  
- **Tokens renovados dinamicamente** a cada projeto.  
- **Fallback com CSV offline** para manter histórico de autores.

---

## Estrutura do Código

```
sca_confirmed_author_comments.py
├── Configuração inicial (URLs, tokens, parâmetros)
├── Funções auxiliares (_is_confirmed, parse_pkg, etc.)
├── GraphQL Query – extrai autor e comentário
├── Classe HistoryIndex – merge com CSV local
├── Funções de paginação (projetos, scans, resultados)
├── collect_confirmed_sca() – coleta principal
└── export_report() – gera Excel/CSV
```

---

☆彡
