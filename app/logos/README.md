# Logos das operadoras

Coloque aqui um arquivo por operadora, **nomeado exatamente pela chave** da operadora.
O cotador carrega `/app/logos/<chave>.svg` e, se faltar, tenta `.png`; se nenhum dos
dois existir, cai no fallback (bolinha colorida + nome em texto). Não quebra a tela.

Formato: **SVG** (preferido) ou **PNG com fundo transparente**. Como a config atual é
"só a logo" (sem o nome ao lado), o ideal é que o arquivo já contenha o nome escrito
da operadora (logotipo completo, colorido). Exibido a ~20px de altura (object-fit: contain).

## Chaves (11)

- `unity` — Unity Saúde
- `evo` — Evo Saúde
- `plenum` — Plenum Saúde
- `amil` — Amil
- `medsenior` — MedSênior
- `segurosunimed` — Seguros Unimed
- `portosaude` — Porto Saúde
- `bradesco` — Bradesco Saúde
- `bestsenior` — Best Senior
- `sulamerica` — SulAmérica
- `hapvida` — Hapvida

Ex.: `unity.svg`, `amil.png`, `segurosunimed.svg` …
