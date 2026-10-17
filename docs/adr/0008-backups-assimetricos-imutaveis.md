# ADR 0008 — Backups com cifra assimétrica e storage imutável

- Status: Aceito
- Data: 2026-10-15

## Contexto

O pior cenário é a invasão do servidor seguida de ransomware: o atacante lê
os dados e apaga os backups. Ferramentas como restic e Kopia usam chave
simétrica, que precisa ficar no servidor; quem invade o servidor lê todos os
backups.

## Decisão

- Cifra **assimétrica** com age (X25519). O servidor só tem as chaves
  públicas; as privadas ficam no Kit de recuperação do operador. O WAL-G usa
  o modo de chave pública PGP (validar na implementação).
- Destino com **Object Lock**; credencial do servidor sem permissão de apagar;
  retenção feita por regras de ciclo de vida do bucket.
- Verificação do dump **antes** de cifrar (o servidor não consegue decifrar
  depois) + simulado periódico no computador do operador.

## Consequências

- Servidor invadido não lê nem apaga backups.
- Sem deduplicação (arquivos completos comprimidos). Aceitável para o volume
  atual; se volumes ficarem muito grandes, reavaliar um modo com restic para
  eles.
- Restaurar exige a chave privada do operador, entregue só na memória durante
  a restauração.
- Perder todas as chaves = perder os backups. Por isso há duas chaves e o kit
  em papel.

## Atualização (Etapa 9, 2026-10-16)

O WAL não usa WAL-G nem PGP: o `archive_command` do Postgres só copia cada
arquivo para uma caixa de saída no volume de dados, e o hangard cifra com
age para as mesmas chaves públicas e envia. Assim a imagem oficial do
Postgres não muda, nenhuma chave entra no container e o kit tem uma chave
só (age). Detalhes em [09](../09-backups.md#como-ficou-na-implementação-etapa-9).
