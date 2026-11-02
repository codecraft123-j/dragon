# 🐉 Dragon Scanner

Ferramenta de **enumeração passiva de subdomínios** escrita em Go. Consulta fontes **gratuitas e sem chave obrigatória** em paralelo, filtra pelo escopo do alvo e salva uma lista única e ordenada.

## Fontes

Todas gratuitas. As marcadas como confirmadas responderam com sucesso em scan real.

| Fonte | Tipo | Status |
|---|---|---|
| crt.sh | Certificate Transparency | confirmada |
| CertSpotter | Certificate Transparency | confirmada (chave opcional) |
| AlienVault OTX | URLs + DNS passivo | confirmada |
| URLScan.io | Páginas escaneadas | confirmada (chave opcional) |
| RapidDNS | Banco de DNS | confirmada |
| DNSRepo | Banco de DNS | confirmada |
| Assetfinder | Ferramenta externa (opcional) | confirmada |
| Wayback Machine (CDX) | Arquivo da web | em teste |
| Subfinder | Ferramenta externa (opcional) | em teste |

### Chaves opcionais (funcionam sem, a chave só aumenta o limite)

| Fonte | Variável |
|---|---|
| CertSpotter | `CERTSPOTTER_API_KEY` |
| URLScan.io | `URLSCAN_API_KEY` |

## Instalação

Requer [Go](https://go.dev/dl/) instalado.

```bash
go install github.com/codecraft123-j/dragon@latest
```

O binário fica em `~/go/bin/dragon`. Se esse diretório não estiver no PATH:

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Dependências opcionais

`subfinder` e `assetfinder` precisam estar no PATH para serem usados. Se não estiverem, o Dragon avisa e continua com as outras fontes.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
```

## Uso

```bash
# Alvo único
dragon -u example.com

# Lista de alvos
dragon -l alvos.txt

# Saída personalizada, timeout maior e sem banner
dragon -u example.com -o resultado.txt -t 300s -silent

# Listar as fontes
dragon -ls

# Mostrar o motivo das falhas
dragon -u example.com -v
```

### Flags

| Flag | Descrição | Padrão |
|---|---|---|
| `-u` | Alvo único (ex: `example.com`) | — |
| `-l` | Arquivo com lista de alvos, um por linha | — |
| `-o` | Arquivo de saída | `subdomains.txt` |
| `-t` | Timeout por alvo | `90s` |
| `-silent` | Não exibe o banner | `false` |
| `-ls` | Lista as fontes | `false` |
| `-v` | Mostra o motivo das falhas de cada fonte | `false` |

Logs e progresso vão para o `stderr`; os resultados vão para o arquivo de saída, então dá para usar em pipeline:

```bash
dragon -u example.com -silent && cat subdomains.txt | httpx -silent
```

## Como funciona

1. Cada fonte roda em paralelo (goroutines).
2. Os resultados são normalizados: minúsculas, sem `*.`, sem duplicados.
3. Só ficam os hosts que pertencem ao alvo (`alvo.com` ou `*.alvo.com`).
4. A lista final é ordenada e salva em arquivo.
5. Se uma fonte falhar, o Dragon mostra o aviso e continua com as outras.

Fontes gratuitas mudam ou saem do ar com o tempo. Use `-v` para ver quais estão falhando.

## Aviso legal

Use apenas em alvos que você tem **autorização** para testar, como programas de bug bounty dentro do escopo ou ativos próprios. O autor não se responsabiliza pelo uso indevido da ferramenta.

## Autor

**laftman** — [@codecraft123-j](https://github.com/codecraft123-j)
