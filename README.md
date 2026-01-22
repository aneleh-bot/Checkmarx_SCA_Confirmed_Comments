# Script SCA Confirmed Comments ☆彡

Checkmarx One: Relatório de Vulnerabilidades SCA (Confirmadas + Autores + Comentários)

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
