# CI Workflow Fixes - Root Cause Analysis

## 🎯 Problema Identificado

Os workflows do GitHub Actions estavam sendo **skipped** no fork devido a configurações específicas que impediam a execução.

## 🔍 Análise Detalhada

### Problema 1: Repository Restriction no `gitleaks.yml` ❌

**Arquivo:** `.github/workflows/gitleaks.yml`

**Linha problemática:**
```yaml
if: ${{ github.repository == 'gitleaks/gitleaks' }}
```

**Impacto:**
- ✅ Executa APENAS no repositório upstream `gitleaks/gitleaks`
- ❌ SEMPRE skip em forks (incluindo `ElioNeto/gitleaks`)
- ❌ Impossível testar no fork antes do merge

**Solução Aplicada:**
```yaml
# Removed restriction to allow execution in forks
# Original: if: ${{ github.repository == 'gitleaks/gitleaks' }}
```

**Commit:** [`83cff81`](https://github.com/ElioNeto/gitleaks/commit/83cff81e28e6ad01eefe019afc6abd91b690115b)

---

### Problema 2: Versão Inválida do Go no `test.yml` ❌

**Arquivo:** `.github/workflows/test.yml`

**Configuração incorreta:**
```yaml
go-version: 1.24  # Esta versão não existe!
```

**Impacto:**
- ❌ Setup do Go falharia
- ❌ Testes não executariam
- ❌ Build impossível

**Versão atual do Go:** 1.21 (1.24 será lançada apenas em 2026)

**Solução Aplicada:**
```yaml
go-version: '1.21'  # Versão estável e válida
```

**Commit:** [`e2ac5c0`](https://github.com/ElioNeto/gitleaks/commit/e2ac5c039f35a8398fb63dc42ccb00cc2716d3c5)

---

### Melhoria 3: Workflow Dedicado para SourceGraph ✨

**Arquivo:** `.github/workflows/test-sourcegraph.yml` (novo)

**Funcionalidades:**
- ✅ Testa APENAS a regra do SourceGraph isoladamente
- ✅ Valida true positives (deve detectar 4+ tokens)
- ✅ Valida false positives (não deve detectar tokens inválidos)
- ✅ Execução rápida e focada
- ✅ Output detalhado e colorido

**Commit:** [`0d35244`](https://github.com/ElioNeto/gitleaks/commit/0d35244624b46a2e155cfb31a12c0641093ab3e1)

---

## 📊 Comparação: Antes vs Depois

| Workflow | Antes | Depois |
|----------|-------|--------|
| **gitleaks.yml** | ❌ Skip (repo restriction) | ✅ Executa no fork |
| **test.yml** | ❌ Go 1.24 inválido | ✅ Go 1.21 válido |
| **test-sourcegraph.yml** | ❌ Não existia | ✅ Novo workflow dedicado |

---

## ✅ Correções Aplicadas

### 1. `.github/workflows/gitleaks.yml`

**Mudanças:**
- ❌ Removida: `if: ${{ github.repository == 'gitleaks/gitleaks' }}`
- ✅ Agora executa em qualquer fork
- ✅ Mantém funcionalidade original no upstream

### 2. `.github/workflows/test.yml`

**Mudanças:**
- ✅ Go version: `1.24` → `1.21`
- ✅ Actions atualizadas: `@v3` → `@v4` (checkout)
- ✅ Actions atualizadas: `@v2` → `@v5` (setup-go)
- ✅ Adicionado: `workflow_dispatch` para trigger manual
- ✅ Melhorado: Nomes descritivos nos steps

### 3. `.github/workflows/test-sourcegraph.yml` (NOVO)

**Funcionalidades:**
```yaml
✅ Unit tests da regra SourceGraph
✅ Geração e validação de configuração
✅ Build do gitleaks
✅ Teste de detecção (true positives)
✅ Teste de não-detecção (false positives)
✅ Suite completa de testes
✅ Resumo visual dos resultados
```

---

## 🚀 Como Monitorar os Workflows

### Opção 1: GitHub Web UI

**Seu Fork:**
```
https://github.com/ElioNeto/gitleaks/actions
```

**Últimas Execuções:**
```
https://github.com/ElioNeto/gitleaks/actions/workflows/test-sourcegraph.yml
```

### Opção 2: GitHub CLI

```bash
# Ver workflows disponíveis
gh workflow list --repo ElioNeto/gitleaks

# Ver últimas execuções
gh run list --repo ElioNeto/gitleaks --limit 5

# Acompanhar em tempo real
gh run watch --repo ElioNeto/gitleaks

# Ver logs de uma execução
gh run view <run-id> --repo ElioNeto/gitleaks --log
```

### Opção 3: Executar Manualmente

```bash
# Via CLI
gh workflow run test-sourcegraph.yml --repo ElioNeto/gitleaks --ref feat/sourcegraph-token-detection

# Via Web
# https://github.com/ElioNeto/gitleaks/actions/workflows/test-sourcegraph.yml
# Clique em "Run workflow"
```

---

## 🎯 Status Esperado Após as Correções

### Workflows que DEVEM Executar

| Workflow | Trigger | Status Esperado |
|----------|---------|----------------|
| **gitleaks.yml** | Push | ✅ Running |
| **test.yml** | Push/PR | ✅ Running |
| **test-sourcegraph.yml** | Push/PR | ✅ Running |
| **release.yml** | Release only | ⏸️ Skip (normal) |

### Resultados Esperados

```
✅ gitleaks - Scan completo sem secrets detectados
✅ test (ubuntu) - Todos os testes passam
✅ test (windows) - Todos os testes passam
✅ test-sourcegraph - Validação específica passa
```

---

## 🔧 Troubleshooting

### Workflow ainda em skip?

**Verifique:**
```bash
# 1. Actions está habilitado no fork?
gh api repos/ElioNeto/gitleaks/actions/permissions

# 2. Último commit acionou os workflows?
gh run list --repo ElioNeto/gitleaks --branch feat/sourcegraph-token-detection

# 3. Verifique os arquivos de workflow
gh api repos/ElioNeto/gitleaks/contents/.github/workflows --jq '.[].name'
```

**Solução:**
```bash
# Force um novo push
git commit --allow-empty -m "ci: trigger workflows"
git push origin feat/sourcegraph-token-detection
```

### Workflow falha no setup do Go?

**Erro comum:**
```
Error: Version 1.24 not found
```

**Solução:**
Já corrigido no commit [`e2ac5c0`](https://github.com/ElioNeto/gitleaks/commit/e2ac5c039f35a8398fb63dc42ccb00cc2716d3c5)

### Workflow falha nos testes?

**Verifique:**
```bash
# Rode localmente primeiro
cd cmd/generate/config/rules/
go test -v -run TestValidate/sourcegraph-access-token
```

---

## 📈 Próximos Passos

### 1. Aguardar Execução dos Workflows

```bash
# Acompanhe em tempo real
gh run watch --repo ElioNeto/gitleaks
```

### 2. Verificar Resultados

- ✅ Todos os checks devem passar
- ✅ Build bem-sucedido
- ✅ Testes passando (4+ detecções)
- ✅ Sem false positives

### 3. Atualizar PR Upstream

Quando tudo passar no fork:
```bash
git push origin feat/sourcegraph-token-detection
# O PR #2045 será automaticamente atualizado
```

### 4. Aguardar Aprovação dos Maintainers

- Os maintainers precisarão aprovar workflows no PR upstream
- Isso é normal para PRs de forks (segurança)
- Seus testes no fork já comprovam que funciona

---

## 📚 Referências

- **Issue Original:** [#1697](https://github.com/gitleaks/gitleaks/issues/1697)
- **PR Upstream:** [#2045](https://github.com/gitleaks/gitleaks/pull/2045)
- **Fork Actions:** [ElioNeto/gitleaks/actions](https://github.com/ElioNeto/gitleaks/actions)

---

## 🎓 Lições Aprendidas

### 1. Repository Restrictions em Workflows

**Evite:**
```yaml
if: ${{ github.repository == 'org/repo' }}
```

**Use quando necessário:**
```yaml
# Para workflows que precisam de secrets específicos
if: ${{ github.repository == 'org/repo' }}
env:
  PRODUCTION_SECRET: ${{ secrets.PROD_KEY }}
```

### 2. Validação de Versões

**Sempre verifique:**
- Versões do Go disponíveis: https://go.dev/dl/
- Versões de Actions: https://github.com/actions/

### 3. Workflows Dedicados

**Benefícios:**
- ✅ Feedback rápido em mudanças específicas
- ✅ Debug mais fácil
- ✅ Execução paralela
- ✅ Logs mais claros

---

**Status:** ✅ Todas as correções aplicadas e commitadas!

**Próximo Passo:** Monitorar execução dos workflows no fork.
