// ═══════════════════════════════════════════════════════════════════════
//  dados.js — Saúde Prime · FONTE ÚNICA DE VERDADE
//
//  Para atualizar preços: edite os arrays "valores" de cada produto.
//  Ordem obrigatória das faixas etárias:
//  [0-18, 19-23, 24-28, 29-33, 34-38, 39-43, 44-48, 49-53, 54-58, 59+]
//
//  Para adicionar nova operadora: copie um bloco {key,nome,...} e preencha.
//  Campos de produto:
//    id, nome, aco ('enf'|'apt'|'amb'), tipo ('adesao'|'pme'|'pf'),
//    valores (array de 10 preços)
//  Se "tipo" não informado, o produto é tratado como 'adesao' (padrão).
//  NÃO edite a seção "Transformadores" abaixo da linha divisória.
// ═══════════════════════════════════════════════════════════════════════

window.SP_DATA = [

  // ── UNITY SAÚDE ───────────────────────────────────────────────────────
  {
    key: 'unity', nome: 'Unity Saúde',
    cor: 'var(--unity)', cls: 'on-u',
    reajuste: 'Mai/2026',
    info: 'Adm. Esplendor · Mai/2026 · Taxa assoc. R$ 5,00 · Assoc: UEB, UVA, UNIPRO, ANC, UNSP · Telemedicina gratuita',
    produtos: []
  },

  // ── EVO SAÚDE ─────────────────────────────────────────────────────────
  {
    key: 'evo', nome: 'Evo Saúde',
    cor: 'var(--evo)', cls: 'on-e',
    reajuste: 'Set/2026',
    info: 'Adm. Easyplan · Reajuste set/2026 · Odonto ODONTOGROUP incluso · Telemedicina 24h · Taxa assoc. R$ 5,00',
    produtos: []
  },

  // ── PLENUM SAÚDE ──────────────────────────────────────────────────────
  {
    key: 'plenum', nome: 'Plenum Saúde',
    cor: 'var(--plenum)', cls: 'on-p',
    reajuste: 'Mar/2027',
    info: 'Adm. Easyplan · Reajuste mar/2027 · Adesão e PME · Seguro Viagem AIG + UTI Móvel 24h · Sírio-Libanês (Sigma) · Taxa assoc. R$ 5,00',
    produtos: []
  },

  // ── AMIL ──────────────────────────────────────────────────────────────
  {
    key: 'amil', nome: 'Amil',
    cor: 'var(--amil)', cls: 'on-a',
    reajuste: 'Mai/2026',
    info: 'PME e Adesão · Tabela mai/2026 · PME Porte I 2–29v / Porte II 30–99v · Amil Dental grátis 12 meses · Rede nacional · Reembolso nos planos Platinum',
    produtos: []
  },

  // ── SEGUROS UNIMED PME ────────────────────────────────────────────────
  {
    key: 'segurosunimed', nome: 'Seguros Unimed',
    cor: 'var(--seguros-unimed)', cls: 'on-su',
    reajuste: 'Jul/2025',
    info: 'PME · Planos Nacionais · Compulsório e Facultativo · Tabela jul/2025 · Rede Unimed nacional',
    produtos: []
  },

  // ── MEDSENIOR ─────────────────────────────────────────────────────────
  {
    key: 'medsenior', nome: 'MedSênior',
    cor: 'var(--medsenior)', cls: 'on-ms',
    reajuste: 'A definir',
    info: 'PF e PME · Sem coparticipação · Rede Brasília · Coleta domiciliar Lab. MedSênior · Oficinas do Bem inclusas',
    produtos: []
  },

  // ── PORTO SAÚDE ────────────────────────────────────────────────────────
  {
    key: 'portosaude', nome: 'Porto Saúde',
    cor: 'var(--portosaude)', cls: 'on-ps',
    reajuste: 'A definir',
    info: 'PME · Planos Bronze / Prata / Ouro · Com e sem coparticipação · Rede credenciada DF · Porto Seguro Saúde',
    produtos: []
  },

  // ── BEST SÊNIOR ───────────────────────────────────────────────────────
  {
    key: 'bestsenior', nome: 'Best Sênior',
    cor: 'var(--bestsenior)', cls: 'on-bs',
    reajuste: 'Mai/2026',
    info: 'PF e PME · Planos exclusivos para 44+ · Tabela mai/2026 · 15% desconto promocional nos planos PJ · Rede credenciada DF · Best Sênior Saúde',
    produtos: []
  },

  // ── BRADESCO SAÚDE ────────────────────────────────────────────────────
  {
    key: 'bradesco', nome: 'Bradesco Saúde',
    cor: 'var(--bradesco)', cls: 'on-b',
    reajuste: 'A definir',
    info: 'PME · Planos Nacionais · Tabela jan/2026 · Rede credenciada DF · Bradesco Seguros',
    produtos: []
  },

  // ── SULAMERICA SAÚDE ──────────────────────────────────────────────────
  {
    key: 'sulamerica', nome: 'SulAmérica Saúde',
    cor: 'var(--sulamerica)', cls: 'on-sa',
    reajuste: 'A definir',
    info: 'PME Compulsório · Vigência 12m ou 24m · 3–99 vidas · Com e sem copart 30% · Rede credenciada DF · SulAmérica Seguro Saúde',
    produtos: []
  },

  // ── HAPVIDA ───────────────────────────────────────────────────────────
  {
    key: 'hapvida', nome: 'Hapvida',
    cor: 'var(--hapvida)', cls: 'on-hap',
    reajuste: 'A definir',
    info: 'PME 2–29 vidas · Tabela Brasília · Nosso Médico e Nosso Plano · Com coparticipação parcial ou completa · Rede credenciada DF',
    produtos: []
  }

];

// ═══════════════════════════════════════════════════════════════════════
//  TRANSFORMADORES — não editar abaixo desta linha
// ═══════════════════════════════════════════════════════════════════════

// PLANOS — formato usado pelo cotador-planos-saude.html
window.PLANOS = window.SP_DATA.flatMap(op =>
  op.produtos.map(p => ({
    id:     p.id,
    op:     op.key,
    nome:   p.nome,
    aco:    p.aco,
    tipo:   p.tipo   || 'adesao',
    mod:    p.mod    || null,
    fvidas: p.fvidas || null,
    vig:    p.vig    || null,
    precos: p.valores
  }))
);

// OP_META — formato unificado (usado por cotador e apresentação)
window.OP_META = Object.fromEntries(
  window.SP_DATA.map(op => [op.key, {
    nome: op.nome,
    cor:  op.cor,
    cls:  op.cls,
    info: op.info
  }])
);

// PLANOS_DB — formato usado por apresentacao-executiva.html
const _acoLabel = { enf:'Enfermaria', apt:'Apartamento', amb:'Ambulatorial' };
window.PLANOS_DB = Object.fromEntries(
  window.SP_DATA.map(op => [
    op.key,
    op.produtos.map(p => ({
      id:       p.id,
      nome:     p.nome,
      aco:      _acoLabel[p.aco] || p.aco,
      reajuste: op.reajuste
    }))
  ])
);

// REDE_DATA — rede credenciada por operadora (fonte hardcoded; sobrescrita pelo banco quando disponível)
window.REDE_DATA = {
  unity: {
    adm: 'Adm. Esplendor · Atualizada 04/2026',
    grupos: [
      { titulo: 'Hospitais — Life Vital & Unity Vida', itens: [
        { nome: 'Hosp. Prontonorte', local: 'Asa Norte', tags: ['PS','INT'] },
        { nome: 'Hosp. Santa Lúcia Taguatinga', tags: ['PS','INT'] },
        { nome: 'Hosp. Maria Auxiliadora', tags: ['PS','INT'] },
        { nome: 'Hosp. São Mateus', local: 'Cruzeiro', tags: ['PS','INT','AMB'] },
        { nome: 'Hosp. PAI', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. AMMA', local: 'Águas Claras', tags: ['INT','AMB'] },
        { nome: 'P.S. Fraturas', local: 'Ceilândia', tags: ['PS','INT'] },
        { nome: 'Hosp. Jardim Botânico', tags: ['PS','INT'] },
        { nome: 'Hosp. Santa Luzia', local: 'Luziânia/GO', tags: ['PS','INT'] },
        { nome: 'Hosp. Luciano Chaves', local: 'Formosa/GO', tags: ['INT'] },
      ]},
      { titulo: 'Exclusivos Unity Star', itens: [
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['INT','MAT'] },
        { nome: 'Hospital Home', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hospital Pacini', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'CBV Hosp. de Olhos', tags: ['PS'] },
        { nome: 'Hospital Cerrado', local: 'Valparaíso/GO', tags: ['INT'] },
      ]},
      { titulo: 'Laboratórios', itens: [
        { nome: 'Bom Exame · LAC · Citoprev · Aliança · Sabin (Unity Vida/Star)' },
      ]},
    ],
    rodape: 'Telemedicina isenta. HOB, Inst. Panamericano, Oftalmed Visão, CEME Luziânia e Santa Mônica também credenciados.',
  },
  evo: {
    adm: 'Adm. Easyplan · +166 parceiros no DF',
    grupos: [
      { titulo: 'Hospitais — ONE e NOW', itens: [
        { nome: 'Hospital Brasília', local: 'Lago Sul / Águas Claras', tags: ['PS','INT'] },
        { nome: 'Hospital Home', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['MAT'] },
        { nome: 'Hospital Cerrado', local: 'Valparaíso/GO', tags: ['INT'] },
        { nome: 'Clínicas de Ceilândia', tags: ['PS','INT'] },
        { nome: 'Centro Clínico AMMA', local: 'Águas Claras', tags: ['PS'] },
        { nome: 'HPAES', local: 'São Sebastião', tags: ['INT','AMB'] },
      ]},
      { titulo: 'Plano ONE — Atenção Primária (exclusivo)', itens: [
        { nome: 'Clínica Amparo / Grupo Sabin', local: 'Asa Norte · Lago Norte · Sudoeste · Taguatinga', obs: 'Atendimento primário obrigatório antes do especialista — exceto Oftalmologia' },
      ]},
      { titulo: 'Oftalmologia · Laboratórios', itens: [
        { nome: 'Oftalmed', local: 'Asa Sul · Águas Claras · Taguatinga · Ceilândia' },
        { nome: 'Sabin (ONE e NOW) · Laboratório Exame (NOW)' },
      ]},
    ],
    rodape: 'Urgência nacional via ABRAMGE (+170 prestadores). Odontológico ODONTOGROUP incluso sem custo.',
  },
  plenum: {
    adm: 'Adm. Easyplan · +120 clínicas / 140+ endereços',
    grupos: [
      { titulo: 'Hospitais — Delta, Ômega, Beta, Sigma', itens: [
        { nome: 'Hosp. Sírio-Libanês', local: 'Asa Sul', tags: ['PS','INT'], tagExtra: { label: 'Sigma', cor: '#fef3c7', texto: '#92400e' } },
        { nome: 'Hosp. Brasília', local: 'Lago Sul / Águas Claras', tags: ['PS','INT'] },
        { nome: 'Hosp. Alvorada', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Home', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Daher', local: 'Lago Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. São Mateus', local: 'Cruzeiro', tags: ['INT','AMB'] },
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['INT','MAT'] },
        { nome: 'Hosp. Anchieta', local: 'Taguatinga / Ceilândia', tags: ['PS','INT','MAT'] },
        { nome: 'HPAES', local: 'São Sebastião', tags: ['INT','AMB'] },
        { nome: 'Hosp. Santa Luzia', local: 'Luziânia/GO', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. Cerrado', local: 'Valparaíso/GO', tags: ['INT'] },
        { nome: 'P.S. Fraturas', local: 'Ceilândia', tags: ['PS','INT'] },
      ]},
      { titulo: 'Laboratórios', itens: [
        { nome: 'Exame · Aliança · Dom Bosco · Vitrium · Citoprev · Sabin · Sírio-Libanês Diag. (Sigma)' },
      ]},
    ],
    rodape: 'Seguro Viagem Nacional AIG incluso. UTI Móvel 24h (3 bases).',
  },
  amil: {
    adm: 'Adm. própria · Vigência Mai/2026',
    grupos: [
      { titulo: 'Hospitais — Todos os planos DF', itens: [
        { nome: 'Hosp. Santa Lúcia', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Brasília', local: 'Lago Sul / Águas Claras', tags: ['PS','INT'] },
        { nome: 'Hosp. Home', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Alvorada', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Daher', local: 'Lago Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Anchieta', local: 'Taguatinga / Ceilândia', tags: ['PS','INT','MAT'] },
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['INT','MAT'] },
        { nome: 'Hosp. Santa Luzia', local: 'Luziânia/GO', tags: ['PS','INT'] },
      ]},
      { titulo: 'Exclusivo Platinum — Rede Nacional', itens: [
        { nome: '+600 hospitais credenciados em todo o Brasil' },
        { nome: 'Reembolso por livre escolha (fora da rede credenciada)' },
      ]},
      { titulo: 'Laboratórios', itens: [
        { nome: 'Sabin · DASA (Álvaro) · rede própria Amil' },
      ]},
    ],
    rodape: 'Amil Dental incluso 12 meses grátis (R$ 14,99/mês após). Confirme rede no app Amil ou em amil.com.br/guia-medico.',
  },
  segurosunimed: {
    adm: 'Adm. própria · Abrangência DF + Regiões Administrativas',
    grupos: [
      { titulo: 'Todos os planos — incl. Essencial I / II / III / IV', itens: [
        { nome: 'Hosp. Santa Lúcia', local: 'Asa Norte / Gama / Taguatinga', tags: ['PS','INT'] },
        { nome: 'Hosp. São Mateus', local: 'Cruzeiro', tags: ['PS','INT'] },
        { nome: 'Hosp. Home · Hosp. Alvorada · Hosp. Daher', tags: ['PS','INT'] },
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['INT','MAT'] },
        { nome: 'P.S. das Fraturas', local: 'Ceilândia', tags: ['PS','INT'] },
        { nome: 'Hosp. Anchieta', local: 'Taguatinga / Ceilândia', tags: ['PS','INT'] },
        { nome: 'Hosp. Santa Marta · Anna Nery · Maria Auxiliadora · Prontonorte', tags: ['PS','INT'] },
        { nome: 'Hosp. São Francisco', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. Urológico · Oftalmed / Hosp. da Visão', tags: ['INT'] },
        { nome: 'Unimed Espaço Saúde Cuidar Mais · Hosp. Dr Albert Sabin', tags: ['INT','AMB'] },
      ]},
      { titulo: 'A partir do Completo', itens: [
        { nome: 'HOB — Brasília e Taguatinga Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Águas Claras · Hosp. Pacini', tags: ['PS','INT'] },
        { nome: 'Hosp. Santa Helena', local: 'Brasília', tags: ['PS','INT','MAT'] },
      ]},
      { titulo: 'A partir do Superior', itens: [
        { nome: 'Hosp. do Coração do Brasil · Hosp. Santa Luzia', tags: ['PS','INT'] },
        { nome: 'Hosp. Sírio-Libanês', local: 'Asa Sul', tags: ['INT'] },
        { nome: 'RM Clínica de Reabilitação · CBV — Centro Brasileiro da Visão', tags: ['INT'] },
      ]},
      { titulo: 'Laboratórios', itens: [
        { nome: 'Sabin / DASA Diagnóstica', local: 'Múltiplas unidades', tags: ['AMB'] },
        { nome: 'Fleury / Exame Diagnóstica', local: 'Brasília', tags: ['AMB'] },
      ]},
    ],
    rodape: 'Urgência/Emergência nacional via UE Seguros Unimed (+1.000 prestadores). Planos Essencial: abrangência grupo de municípios (DF + RAs). Confirme rede em segurosunimed.com.br/guia-medico.',
  },
  medsenior: {
    adm: 'Coleta Domiciliar Lab. MedSênior inclusa em todos os planos',
    grupos: [
      { titulo: 'DF3 · DF4 · Black · Infinite (e PME equivalentes)', itens: [
        { nome: 'Unidade MedSênior P.A. 24h',  local: 'SIG',          tags: ['PS','AMB'] },
        { nome: 'Unidade MedSênior P.A. 24h',  local: 'Taguatinga',   tags: ['PS','AMB'] },
        { nome: 'Unidade MedSênior',           local: 'Asa Sul',      tags: ['AMB'] },
        { nome: 'Unidade MedSênior',           local: 'Taguatinga',   tags: ['AMB'] },
        { nome: 'Unidade MedSênior',           local: 'Águas Claras', tags: ['AMB'] },
        { nome: 'C. Oftalmológico MedSênior',  local: 'Asa Sul',      tags: ['AMB'] },
        { nome: 'C. Oftalmológico MedSênior',  local: 'Águas Claras', tags: ['AMB'] },
        { nome: 'Centro de Diagnóstico SIG',                          tags: ['AMB'] },
        { nome: 'Hospital Alvorada Brasília',                         tags: ['INT'], obs: 'PS 24h incluído no Infinite' },
        { nome: 'Hospital Daher',                                     tags: ['INT'], obs: 'PS 24h incluído no Infinite · PSO disponível em DF3/DF4/Black' },
        { nome: 'Hospital Home',               local: 'Asa Sul',      tags: ['INT'], obs: 'PS 24h incluído no Infinite' },
        { nome: 'Hospital Santa Marta',                               tags: ['INT'], obs: 'PS 24h incluído no Infinite' },
        { nome: 'Laboratório LAPAC',                                  tags: ['AMB'] },
        { nome: 'Laboratório Sabin',                                  tags: ['AMB'] },
        { nome: 'Laboratório Exame',                                  tags: ['AMB'] },
      ]},
      { titulo: 'Black · Infinite (adiciona à rede DF)', itens: [
        { nome: 'Hospital Brasília', local: 'Lago Sul',     tags: ['INT'], obs: 'PS 24h incluído no Infinite' },
        { nome: 'Hospital Brasília', local: 'Águas Claras', tags: ['INT'], obs: 'PS 24h incluído no Infinite' },
        { nome: 'Hospital Sírio Libanês',                   tags: ['INT'] },
      ]},
    ],
    rodape: 'Coleta domiciliar Lab. MedSênior inclusa · Rede DF exclusiva para 49+ · Sem coparticipação · Oficinas do Bem inclusas',
  },
  portosaude: {
    adm: 'Porto Seguro Saúde · PME · Rede credenciada DF',
    grupos: [
      { titulo: 'Todos os planos (Bronze / Prata / Ouro)', itens: [
        { nome: 'Hosp. Santa Lúcia', local: 'Asa Norte / Gama / Taguatinga', tags: ['PS','INT'] },
        { nome: 'Hosp. Anchieta', local: 'Taguatinga / Ceilândia', tags: ['PS','INT'] },
        { nome: 'Hosp. Brasília', local: 'Lago Sul / Águas Claras', tags: ['PS','INT'] },
        { nome: 'Hosp. Home · Hosp. Alvorada', tags: ['PS','INT'] },
        { nome: 'Hosp. São Mateus', local: 'Cruzeiro', tags: ['PS','INT'] },
        { nome: 'Hosp. Santa Marta · Hosp. Daher', tags: ['PS','INT'] },
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['INT','MAT'] },
        { nome: 'P.S. das Fraturas', local: 'Ceilândia', tags: ['PS','INT'] },
        { nome: 'Sabin / DASA Diagnóstica', local: 'Múltiplas unidades', tags: ['AMB'] },
      ]},
      { titulo: 'Planos com Apartamento (P420 / Ouro)', itens: [
        { nome: 'Hosp. Santa Helena', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. do Coração do Brasil', tags: ['PS','INT'] },
        { nome: 'Hosp. DF Star', local: 'Brasília', tags: ['INT'] },
      ]},
    ],
    rodape: 'Rede PME Porto Saúde no DF. Coparticipação parcial nos planos "Com copart". Confirme rede atualizada em portosaude.com.br ou com o corretor.',
  },
  bestsenior: {
    adm: 'Tabela Mar–Abr/2026 · Exclusivo 44+ · Best Sênior Saúde',
    grupos: [
      { titulo: 'Classic · Prime · Platinum', itens: [
        { nome: 'Hospital Santa Lúcia',                                    local: 'Gama',      tags: ['PS','INT','AMB'] },
        { nome: 'Hospital Anchieta Ceilândia São Francisco (Kora Saúde)',  local: 'Ceilândia', tags: ['PS','INT','AMB'] },
        { nome: 'CBV Hospital de Olhos',                                                       tags: ['PS','AMB']       },
        { nome: 'Laboratório Santa Paula',                                                     tags: ['AMB']            },
      ]},
      { titulo: 'Prime · Platinum (adiciona à rede Classic)', itens: [
        { nome: 'Hospital Prontonorte',                local: 'Asa Norte',  tags: ['PS','INT','AMB'] },
        { nome: 'Unidade Avançada Santa Lúcia',              local: 'Taguatinga', tags: ['PS','AMB']       },
        { nome: 'Hospital Anchieta Taguatinga (Kora Saúde)', local: 'Taguatinga', tags: ['INT','AMB'], obs: 'PS 24h incluído no Platinum' },
        { nome: 'Hospital Santa Lúcia Sul',                  local: 'Asa Sul',    tags: ['INT','AMB'], obs: 'PS 24h incluído no Platinum' },
        { nome: 'Laboratório Sabin',                                               tags: ['AMB']       },
      ]},
    ],
    rodape: 'Rede DF exclusiva para 44+. Confirme rede atualizada com o corretor ou no site bestsenior.com.br.',
  },
  bradesco: {
    adm: 'Bradesco Seguros · PME · Rede Nacional',
    grupos: [
      { titulo: 'Nacional Plus 4 e Premium 6 — Todos os planos Apt', itens: [
        { nome: 'Hosp. Santa Helena', local: 'Asa Norte', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. Prontonorte · Santa Lúcia Sul', local: 'Asa Norte / Asa Sul', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. Alvorada · H. Home · H. Daher', tags: ['PS','INT'] },
        { nome: 'Hosp. DF Star · H. do Coração do Brasil', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. Santa Luzia · Santa Marta', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Sírio-Libanês Brasília IV', local: 'Asa Sul', tags: ['PS','INT'] },
        { nome: 'Hosp. São Mateus', local: 'Cruzeiro', tags: ['PS','INT'] },
        { nome: 'Hosp. Anchieta', local: 'Ceilândia / Taguatinga', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. Santa Marta Taguatinga · H. Mantevida', tags: ['PS','INT'] },
        { nome: 'Hosp. Brasília', local: 'SHIS', tags: ['INT'] },
        { nome: 'Maternidade Brasília', local: 'Sudoeste', tags: ['INT','MAT'] },
        { nome: 'Hosp. Águas Claras', local: 'Brasília', tags: ['PS','INT'] },
        { nome: 'Maria Auxiliadora', local: 'Gama', tags: ['PS','INT','MAT'] },
      ]},
      { titulo: 'Nacional Flex — Enfermaria', itens: [
        { nome: 'Hosp. Santa Helena · Prontonorte / Sta Lúcia Sul / Maria Auxiliadora', tags: ['PS','INT','MAT'] },
        { nome: 'Hosp. Alvorada · H. Home · H. Daher · Maternidade Brasília', tags: ['PS','INT'] },
        { nome: 'Hosp. Anchieta Ceilândia · H. Mantevida · Sta Marta Taguatinga', tags: ['PS','INT'] },
      ]},
      { titulo: 'Efetivo — Rede reduzida (Enfermaria)', itens: [
        { nome: 'Prontonorte / Sta Lúcia Sul / Maria Auxiliadora', tags: ['INT','MAT'] },
        { nome: 'Cto. Clínico Recanto', tags: ['INT'] },
      ]},
      { titulo: 'Laboratórios', itens: [
        { nome: 'Exame · Imeb · Sabin · Micra', local: 'Todos os planos' },
        { nome: 'Brasiliense · Fleury', local: 'Nacional Plus 4 e Premium 6' },
      ]},
    ],
    rodape: 'Rede nacional Bradesco. Confirme rede atualizada em bradescosaude.com.br ou com o corretor.',
  },

  sulamerica: {
    adm: 'Lâmina Centro-Oeste · Março/2025',
    grupos: [
      { titulo: 'Hospitais', itens: [
        { nome: 'DF Star', local: 'Brasília', tags: ['PS','INT'], tagExtra: { label: '★ Luxo', cor: '#fef9c3', texto: '#78350f' } },
        { nome: 'Hospital Alvorada de Brasília', local: 'Brasília', tags: ['PS','INT'] },
        { nome: 'Hospital Anchieta', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hospital Brasília', local: 'Brasília', tags: ['PS','INT'] },
        { nome: 'Hospital do Coração do Brasil', local: 'Brasília', tags: ['INT'] },
        { nome: 'Hospital Daher Lago Sul', local: 'Lago Sul', tags: ['PS','INT'] },
        { nome: 'Hospital Maria Auxiliadora', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hospital Santa Helena', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hospital Santa Luzia', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hospital São Francisco', local: 'Brasília', tags: ['PS','INT','MAT'] },
        { nome: 'Hospital Santa Marta', local: 'Taguatinga', tags: ['PS','INT','MAT'] },
        { nome: 'Maternidade Brasília', local: 'Brasília', tags: ['MAT'] },
        { nome: 'ProUnidade', local: 'Brasília', tags: ['PS','INT'] },
        { nome: 'Hospital Águas Claras', local: 'Águas Claras', tags: ['PS','INT'] },
      ]},
      { titulo: 'Laboratórios', itens: [
        { nome: 'Laboratório Sabin', local: 'Brasília', tags: ['AMB'] },
        { nome: 'HSL Unidade Brasília III', local: 'Brasília', tags: ['INT','AMB'] },
        { nome: 'Lab Flanalto', local: 'Brasília', tags: ['AMB'] },
      ]},
      { titulo: 'Oftalmologia', itens: [
        { nome: 'Visão Institutos Oftalmológicos', local: 'Brasília', tags: ['AMB'] },
        { nome: 'Hospital de Olhos do Gama', local: 'Gama', tags: ['INT'] },
      ]},
    ],
    rodape: 'Rede válida para Brasília/DF · Planos PME · Confirme cobertura por produto em sulamerica.com.br',
  },
};

// ── Sincronização com banco de dados ────────────────────────────────────────
// Para cada operadora que tiver planos no banco, substitui TODOS os planos
// hardcoded dessa operadora pelos planos do banco (o banco é a fonte de verdade).
// Operadoras sem planos no banco continuam usando o hardcoded como fallback.
(async function sincronizarCatalogo() {
  try {
    const _tok = (window.parent && window.parent.token && window.parent.token()) || null;
    const r = await fetch('/api/catalogo', {headers: _tok ? {'Authorization': 'Bearer ' + _tok} : {}});
    if (!r.ok) return;   // sem sessão → mantém o catálogo hardcoded; o cotador derruba p/ login
    const { planos, operadoras, rede } = await r.json();
    if (!planos.length && !Object.keys(operadoras).length) return;
    // Agrupa planos do banco por operadora
    const porOp = {};
    planos.forEach(p => { (porOp[p.op] = porOp[p.op] || []).push(p); });
    // Substitui planos hardcoded pelos do banco operadora a operadora
    Object.keys(porOp).forEach(opKey => {
      window.PLANOS = window.PLANOS.filter(p => p.op !== opKey);
      porOp[opKey].forEach(p => window.PLANOS.push(p));
    });
    // Atualiza metadados de operadoras (merge por propriedade para preservar cor/cls do SP_DATA)
    Object.entries(operadoras).forEach(([k, v]) => {
      if (window.OP_META[k]) { Object.assign(window.OP_META[k], v); }
      else { window.OP_META[k] = v; }
    });
    // Atualiza rede credenciada (banco sobrescreve hardcoded por operadora)
    if (rede && typeof rede === 'object') {
      Object.keys(rede).forEach(opKey => {
        if (rede[opKey]) window.REDE_DATA[opKey] = rede[opKey];
      });
    }
    if (typeof render === 'function') render();
    if (typeof renderRedeTab === 'function') renderRedeTab();
  } catch(e) {}
})();
