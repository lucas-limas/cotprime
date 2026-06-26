import os
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_connection():
    if DATABASE_URL:
        import psycopg2
        from psycopg2.extras import RealDictCursor

        class _Result:
            def __init__(self, c):
                self._c = c
            def fetchone(self):
                return self._c.fetchone()
            def fetchall(self):
                return self._c.fetchall()

        class _Conn:
            def __init__(self):
                self._pg = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
            def execute(self, sql, params=()):
                c = self._pg.cursor()
                c.execute(sql.replace("?", "%s"), params or ())
                return _Result(c)
            def commit(self):
                self._pg.commit()
            def rollback(self):
                self._pg.rollback()
            def close(self):
                self._pg.close()

        return _Conn()

    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "saude_prime.db"))
    conn.row_factory = sqlite3.Row
    return conn


def insert_returning(conn, sql, params, table):
    """Executa um INSERT e retorna a linha inserida, seguro sob concorrência.

    PostgreSQL: INSERT ... RETURNING *. SQLite: cursor.lastrowid + SELECT por id.
    Evita o padrão "SELECT ... ORDER BY id DESC LIMIT 1", que pode retornar a
    linha de outro request concorrente. Faz o commit antes de retornar.
    """
    if DATABASE_URL:
        res = conn.execute(sql + " RETURNING *", params)
        row = res.fetchone()
        conn.commit()
        return row
    cur = conn.execute(sql, params)
    new_id = cur.lastrowid
    conn.commit()
    return conn.execute(f"SELECT * FROM {table} WHERE id = ?", (new_id,)).fetchone()


def _migrations_pg(conn):
    safe = [
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE users ADD COLUMN corretora_id INTEGER",
        "ALTER TABLE users ADD COLUMN tentativas_login INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN bloqueado_ate TEXT",
        "ALTER TABLE users ADD COLUMN session_token TEXT",
        "ALTER TABLE cotacoes ADD COLUMN corretora_id INTEGER",
        # fvidas deve ser TEXT (ex: '02-29', '05-29', '30-99'), não INTEGER
        "ALTER TABLE planos ALTER COLUMN fvidas TYPE TEXT USING fvidas::TEXT",
        # Renomeia códigos Amil para bater com IDs de dados.js (mapeamento por preço)
        "UPDATE planos SET codigo = 'am_ad_ct_1'  WHERE codigo = 'a1'",
        "UPDATE planos SET codigo = 'am_ad_ct_2'  WHERE codigo = 'a2'",
        "UPDATE planos SET codigo = 'am_ad_ct_3'  WHERE codigo = 'a3'",
        "UPDATE planos SET codigo = 'am_ad_ct_4'  WHERE codigo = 'a4'",
        "UPDATE planos SET codigo = 'am_ad_ct_5'  WHERE codigo = 'a5'",
        "UPDATE planos SET codigo = 'am_ad_ct_6'  WHERE codigo = 'a6'",
        "UPDATE planos SET codigo = 'am_ad_ct_9'  WHERE codigo = 'a7'",
        "UPDATE planos SET codigo = 'am_ad_ct_10' WHERE codigo = 'a8'",
        "UPDATE planos SET codigo = 'am_ad_ct_7'  WHERE codigo = 'a9'",
        "UPDATE planos SET codigo = 'am_ad_ct_8'  WHERE codigo = 'a10'",
        "UPDATE planos SET codigo = 'am_ad_cp_1'  WHERE codigo = 'a11'",
        "UPDATE planos SET codigo = 'am_ad_cp_2'  WHERE codigo = 'a12'",
        "UPDATE planos SET codigo = 'am_ad_cp_3'  WHERE codigo = 'a13'",
        "UPDATE planos SET codigo = 'am_ad_cp_4'  WHERE codigo = 'a14'",
        "UPDATE planos SET codigo = 'am_ad_cp_5'  WHERE codigo = 'a15'",
        "UPDATE planos SET codigo = 'am_ad_cp_6'  WHERE codigo = 'a16'",
        "UPDATE planos SET codigo = 'am_ad_cp_9'  WHERE codigo = 'a17'",
        "UPDATE planos SET codigo = 'am_ad_cp_10' WHERE codigo = 'a18'",
        "UPDATE planos SET codigo = 'am_ad_cp_7'  WHERE codigo = 'a19'",
        "UPDATE planos SET codigo = 'am_ad_cp_8'  WHERE codigo = 'a20'",
        # Desativa planos Unity Life Vital (u1/u2) removidos do dados.js
        "UPDATE planos SET ativo = 0 WHERE codigo IN ('u1', 'u2')",
        # Rede credenciada: metadados na tabela operadoras
        "ALTER TABLE operadoras ADD COLUMN rede_adm TEXT",
        "ALTER TABLE operadoras ADD COLUMN rede_rodape TEXT",
        # Etapa 2: atualizado_em em todas as tabelas existentes
        "ALTER TABLE corretoras ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE users ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE cotacoes ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE audit_log ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE operadoras ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE planos ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE rede_credenciada ADD COLUMN atualizado_em TEXT",
        # Etapa 2: FKs novas em cotacoes (usuario TEXT coexiste com usuario_id)
        "ALTER TABLE cotacoes ADD COLUMN cliente_id INTEGER REFERENCES clientes(id)",
        "ALTER TABLE cotacoes ADD COLUMN usuario_id INTEGER REFERENCES users(id)",
        # Etapa 2: FK nova em audit_log
        "ALTER TABLE audit_log ADD COLUMN usuario_id INTEGER REFERENCES users(id)",
        # Etapa 2: índices de performance
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
        "CREATE INDEX IF NOT EXISTS idx_users_corretora_id ON users(corretora_id)",
        "CREATE INDEX IF NOT EXISTS idx_cotacoes_usuario ON cotacoes(usuario)",
        "CREATE INDEX IF NOT EXISTS idx_cotacoes_usuario_criado ON cotacoes(usuario, criado_em)",
        "CREATE INDEX IF NOT EXISTS idx_planos_operadora_id ON planos(operadora_id)",
        "CREATE INDEX IF NOT EXISTS idx_rede_operadora_id ON rede_credenciada(operadora_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_usuario ON audit_log(usuario)",
        # Etapa 2: remover ON DELETE CASCADE de users → corretoras (soft delete via ativo=0)
        "ALTER TABLE users DROP CONSTRAINT IF EXISTS users_corretora_id_fkey",
        "ALTER TABLE users ADD CONSTRAINT users_corretora_id_fkey FOREIGN KEY (corretora_id) REFERENCES corretoras(id)",
        # Etapa 3: renomear campos abreviados em planos
        "ALTER TABLE planos RENAME COLUMN aco TO acomodacao",
        "ALTER TABLE planos RENAME COLUMN fvidas TO faixa_vidas",
        "ALTER TABLE planos RENAME COLUMN mod TO moderador",
        "ALTER TABLE planos RENAME COLUMN vig TO mes_vigencia",
        # Etapa 3: Hapvida — inserir operadora se não existir
        "INSERT INTO operadoras (chave, nome, info, ordem) VALUES ('hapvida', 'Hapvida', 'PME 2–29 vidas \xb7 Tabela Bras\xedlia \xb7 Nosso M\xe9dico e Nosso Plano \xb7 Com coparticipa\xe7\xe3o parcial ou completa \xb7 Rede credenciada DF', 11) ON CONFLICT (chave) DO NOTHING",
        # Etapa 3: Hapvida — inserir planos (subquery garante operadora_id correto)
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cp_enf', id, 'Copart Parcial — Nosso M\xe9dico (Enf)', 'enf', 'pme', '02-29', '[147.09,164.74,184.51,212.19,244.02,290.38,362.98,453.73,771.34,863.90]', 1 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cp_apt', id, 'Copart Parcial — Nosso M\xe9dico (Apt)', 'apt', 'pme', '02-29', '[220.58,247.05,276.70,318.21,365.94,435.47,544.34,680.43,1156.73,1295.54]', 2 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cc_enf', id, 'Copart Completa — Nosso M\xe9dico (Enf)', 'enf', 'pme', '02-29', '[129.46,145.00,162.40,186.76,214.77,255.58,319.48,399.35,678.90,760.37]', 3 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cc_apt', id, 'Copart Completa — Nosso M\xe9dico (Apt)', 'apt', 'pme', '02-29', '[194.12,217.41,243.50,280.03,322.03,383.22,479.03,598.79,1017.94,1140.09]', 4 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cp_amb', id, 'Copart Parcial — Nosso Plano (Amb)', 'amb', 'pme', '02-29', '[148.42,166.23,186.18,214.11,246.23,293.01,366.26,457.83,778.31,871.71]', 5 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cp_enf', id, 'Copart Parcial — Nosso Plano (Enf)', 'enf', 'pme', '02-29', '[163.26,182.85,204.79,235.51,270.84,322.30,402.88,503.60,856.12,958.85]', 6 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cp_apt', id, 'Copart Parcial — Nosso Plano (Apt)', 'apt', 'pme', '02-29', '[244.93,274.32,307.24,353.33,406.33,483.53,604.41,755.51,1284.37,1438.40]', 7 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cc_amb', id, 'Copart Completa — Nosso Plano (Amb)', 'amb', 'pme', '02-29', '[120.72,135.21,151.44,174.16,200.28,238.33,297.91,372.39,633.06,709.03]', 8 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cc_enf', id, 'Copart Completa — Nosso Plano (Enf)', 'enf', 'pme', '02-29', '[143.68,160.92,180.23,207.26,232.35,282.64,354.55,443.19,753.48,843.83]', 9 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cc_apt', id, 'Copart Completa — Nosso Plano (Apt)', 'apt', 'pme', '02-29', '[215.54,241.40,270.37,310.93,357.57,425.51,531.89,664.86,1130.26,1265.89]', 10 FROM operadoras WHERE chave='hapvida' ON CONFLICT (codigo) DO NOTHING",
        # Etapa 4: remover cls da tabela operadoras (cor voltou como fonte única — ver fim da lista)
        "ALTER TABLE operadoras DROP COLUMN IF EXISTS cls",
        # Etapa 4: 6 operadoras novas (MedSenior, Porto Saude, Best Senior, Bradesco, Seguros Unimed, SulAmerica)
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms1', id, 'Sem copart — DF3 Enfermaria', 'enf', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,803.5,964.2,1263.1]', 1 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms2', id, 'Sem copart — DF4 Apartamento', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,964.19,1157.03,1515.71]', 2 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms3', id, 'Sem copart — Black Apartamento', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1205.92,1447.1,1895.7]', 3 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms4', id, 'Sem copart — Infinite Apartamento', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1818.3,2181.96,2858.37]', 4 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms5', id, 'PME — DF Enfermaria', 'enf', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,723.14,867.77,1136.78]', 5 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms6', id, 'PME — DF Apartamento', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,867.78,1041.34,1364.16]', 6 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms7', id, 'PME — Black Apartamento', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1085.34,1302.41,1706.16]', 7 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms8', id, 'PME — Infinite Apartamento', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1487.7,1785.24,2338.66]', 8 FROM operadoras WHERE chave='medsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_1', id, 'Sem copart — Bronze Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[243.53,295.33,356.27,407.87,441.93,456.4,545.18,586.91,725.17,1218.96]', 1 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_2', id, 'Com copart — Bronze Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[187.52,227.41,274.33,314.06,340.29,351.43,419.79,451.92,558.38,938.6]', 2 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_3', id, 'Sem copart — Prata Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[287.92,349.16,421.2,482.21,522.48,539.58,644.54,693.88,857.34,1441.12]', 3 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_4', id, 'Com copart — Prata Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[221.7,268.85,324.33,371.3,402.31,415.48,496.3,534.29,660.15,1109.66]', 4 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_5', id, 'Sem copart — P420', 'apt', 'pme', NULL, NULL, NULL, '[414.59,502.78,606.52,694.36,752.35,776.98,928.12,999.16,1234.54,2075.16]', 5 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_6', id, 'Com copart — P420', 'apt', 'pme', NULL, NULL, NULL, '[339.96,412.28,497.35,569.38,616.92,637.12,761.06,819.31,1012.32,1701.53]', 6 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_7', id, 'Sem copart — Ouro Brasília Pro', 'apt', 'pme', NULL, NULL, NULL, '[381.88,463.11,558.66,639.57,692.98,715.67,854.89,920.32,1137.13,1911.42]', 7 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_8', id, 'Com copart — Ouro Brasília Pro', 'apt', 'pme', NULL, NULL, NULL, '[313.14,379.75,458.1,524.45,568.25,586.85,701.01,754.66,932.44,1567.36]', 8 FROM operadoras WHERE chave='portosaude' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf1', id, 'Sem copart — Classic (Enf)', 'enf', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,676.09,851.88,1090.4,1504.75]', 1 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf2', id, 'Sem copart — Classic (Apt)', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,829.65,1045.37,1338.07,1846.54]', 2 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf3', id, 'Sem copart — Prime (Apt)', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,982.49,1237.94,1584.56,2186.69]', 3 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf4', id, 'Sem copart — Platinum (Apt)', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,1189.9,1499.28,1919.08,2648.33]', 4 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme1', id, 'Sem copart — Classic PJ (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,608.48,766.69,981.36,1353.64]', 5 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme2', id, 'Sem copart — Classic PJ (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,746.69,940.84,1204.26,1661.89]', 6 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme3', id, 'Sem copart — Prime PJ (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,884.24,1114.15,1426.1,1968.02]', 7 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme4', id, 'Sem copart — Platinum PJ (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,1070.91,1349.36,1727.17,2383.5]', 8 FROM operadoras WHERE chave='bestsenior' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_1', id, 'Sem copart — Nacional Plus 4 (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[1111.89,1312.03,1587.55,1905.08,2171.76,2236.91,2723.58,3203.48,3812.14,6670.86]', 1 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_2', id, 'Sem copart — Premium 6 (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[1535.55,1811.95,2192.44,2630.95,2999.26,3089.24,3761.34,4424.09,5264.67,9212.65]', 2 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_3', id, 'Copart total — Nacional Plus 4 (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[889.51,1049.62,1270.03,1524.05,1737.4,1789.52,2178.85,2562.76,3049.68,5336.64]', 3 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_4', id, 'Sem copart — Efetivo (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[400.01,472.01,571.13,685.36,781.3,804.74,979.81,1152.46,1371.43,2399.87]', 4 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_5', id, 'Sem copart — Nacional Flex (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[466.28,550.22,665.76,798.91,910.76,938.08,1142.16,1343.41,1598.66,2797.5]', 5 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_6', id, 'Copart total — Efetivo (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[308.01,363.45,439.77,527.73,601.6,619.65,754.46,887.39,1056.0,1847.9]', 6 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_7', id, 'Copart total — Nacional Flex (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[359.04,423.67,512.63,615.16,701.28,722.32,879.47,1034.43,1230.97,2154.07]', 7 FROM operadoras WHERE chave='bradesco' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_1', id, 'Sem copart — Compacto', 'enf', 'pme', '02-04', 'comp', NULL, '[516.84,632.61,792.11,875.32,932.33,1081.49,1292.82,1550.52,1840.83,3101.03]', 1 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_2', id, 'Com copart — Compacto', 'enf', 'pme', '02-04', 'comp', NULL, '[382.84,468.6,586.75,648.38,690.61,801.1,957.65,1148.53,1363.57,2297.06]', 2 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '02-04', 'comp', NULL, '[580.25,710.22,889.29,982.71,1046.71,1214.17,1451.43,1740.74,2066.67,3481.49]', 3 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_4', id, 'Com copart — Efetivo', 'apt', 'pme', '02-04', 'comp', NULL, '[429.81,526.09,658.73,727.93,775.34,899.38,1075.13,1289.44,1530.86,2578.88]', 4 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_5', id, 'Sem copart — Completo', 'apt', 'pme', '02-04', 'comp', NULL, '[686.94,840.82,1052.81,1163.41,1239.18,1437.43,1718.32,2060.83,2446.69,4121.67]', 5 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_6', id, 'Com copart — Completo', 'apt', 'pme', '02-04', 'comp', NULL, '[508.85,622.83,779.86,861.78,917.91,1064.76,1272.83,1526.54,1812.36,3053.09]', 6 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_7', id, 'Sem copart — Superior', 'apt', 'pme', '02-04', 'comp', NULL, '[760.09,930.35,1164.91,1287.29,1371.12,1590.49,1901.29,2280.27,2707.21,4560.53]', 7 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_8', id, 'Com copart — Superior', 'apt', 'pme', '02-04', 'comp', NULL, '[608.07,744.28,931.93,1029.83,1096.9,1272.39,1521.03,1824.21,2165.77,3648.42]', 8 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '02-04', 'comp', NULL, '[843.75,1032.74,1293.12,1428.97,1522.03,1765.54,2110.55,2531.24,3005.17,5062.47]', 9 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '02-04', 'comp', NULL, '[675.0,826.2,1034.5,1143.17,1217.63,1412.43,1688.44,2024.99,2404.14,4049.98]', 10 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_11', id, 'Sem copart — Sênior', 'apt', 'pme', '02-04', 'comp', NULL, '[1615.57,1977.45,2476.02,2736.13,2914.32,3380.58,4041.18,4846.7,5754.17,9693.41]', 11 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_12', id, 'Com copart — Sênior', 'apt', 'pme', '02-04', 'comp', NULL, '[1404.84,1719.53,2153.06,2379.24,2534.19,2939.63,3514.07,4214.52,5003.62,8429.05]', 12 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_1', id, 'Sem copart — Compacto', 'enf', 'pme', '05-29', 'comp', NULL, '[458.88,561.66,703.27,777.15,827.77,960.2,1147.83,1376.63,1634.38,2753.25]', 13 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_2', id, 'Com copart — Compacto', 'enf', 'pme', '05-29', 'comp', NULL, '[339.91,416.05,520.94,575.67,613.16,711.26,850.25,1019.72,1210.65,2039.45]', 14 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '05-29', 'comp', NULL, '[515.17,630.57,789.55,872.5,929.32,1078.0,1288.65,1545.52,1834.89,3091.04]', 15 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_4', id, 'Com copart — Efetivo', 'apt', 'pme', '05-29', 'comp', NULL, '[381.61,467.09,584.85,646.29,688.39,798.52,954.56,1144.83,1359.18,2289.66]', 16 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_5', id, 'Sem copart — Completo', 'apt', 'pme', '05-29', 'comp', NULL, '[609.9,746.52,934.74,1032.93,1100.21,1276.22,1525.61,1829.71,2172.29,3659.42]', 17 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_6', id, 'Com copart — Completo', 'apt', 'pme', '05-29', 'comp', NULL, '[451.78,552.98,692.4,765.14,814.97,945.35,1130.08,1355.34,1609.11,2710.68]', 18 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_7', id, 'Sem copart — Superior', 'apt', 'pme', '05-29', 'comp', NULL, '[674.84,826.01,1034.27,1142.92,1217.35,1412.11,1688.06,2024.53,2403.6,4049.07]', 19 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_8', id, 'Com copart — Superior', 'apt', 'pme', '05-29', 'comp', NULL, '[539.88,660.81,827.41,914.33,973.88,1129.69,1350.45,1619.63,1922.88,3239.26]', 20 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '05-29', 'comp', NULL, '[749.12,916.92,1148.1,1268.71,1351.34,1567.53,1873.85,2247.36,2668.14,4494.72]', 21 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '05-29', 'comp', NULL, '[599.3,733.54,918.48,1014.97,1081.07,1254.03,1499.08,1797.89,2134.51,3595.78]', 22 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_11', id, 'Sem copart — Sênior', 'apt', 'pme', '05-29', 'comp', NULL, '[1434.38,1755.68,2198.33,2429.27,2587.48,3001.45,3587.96,4303.15,5108.84,8606.29]', 23 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_12', id, 'Com copart — Sênior', 'apt', 'pme', '05-29', 'comp', NULL, '[1247.29,1526.68,1911.6,2112.41,2249.98,2609.95,3119.97,3741.87,4442.47,7483.73]', 24 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_1', id, 'Sem copart — Compacto', 'enf', 'pme', '30-99', 'comp', NULL, '[420.23,514.37,644.05,711.71,758.06,879.34,1051.17,1260.7,1496.75,2521.4]', 25 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_2', id, 'Com copart — Compacto', 'enf', 'pme', '30-99', 'comp', NULL, '[311.28,381.01,477.07,527.19,561.53,651.36,778.65,933.85,1108.7,1867.71]', 26 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '30-99', 'comp', NULL, '[471.79,577.47,723.07,799.02,851.06,987.22,1180.14,1415.37,1680.37,2830.74]', 27 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_4', id, 'Com copart — Efetivo', 'apt', 'pme', '30-99', 'comp', NULL, '[349.47,427.76,535.6,591.87,630.42,731.27,874.17,1048.42,1244.72,2096.84]', 28 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_5', id, 'Sem copart — Completo', 'apt', 'pme', '30-99', 'comp', NULL, '[558.54,683.66,856.02,945.95,1007.56,1168.75,1397.14,1675.63,1989.36,3351.26]', 29 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_6', id, 'Com copart — Completo', 'apt', 'pme', '30-99', 'comp', NULL, '[413.74,506.41,634.09,700.7,746.34,865.74,1034.92,1241.21,1473.6,2482.42]', 30 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_7', id, 'Sem copart — Superior', 'apt', 'pme', '30-99', 'comp', NULL, '[618.02,756.45,947.17,1046.67,1114.84,1293.2,1545.9,1854.05,2201.19,3708.1]', 31 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_8', id, 'Com copart — Superior', 'apt', 'pme', '30-99', 'comp', NULL, '[494.41,605.16,757.74,837.34,891.87,1034.56,1236.72,1483.24,1760.95,2966.48]', 32 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '30-99', 'comp', NULL, '[686.04,839.71,1051.42,1161.87,1237.54,1435.53,1716.05,2058.11,2443.46,4116.22]', 33 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '30-99', 'comp', NULL, '[548.83,671.77,841.14,929.5,990.03,1148.42,1372.84,1646.49,1954.76,3292.97]', 34 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_11', id, 'Sem copart — Sênior', 'apt', 'pme', '30-99', 'comp', NULL, '[1313.59,1607.84,2013.21,2224.7,2369.59,2748.69,3285.82,3940.78,4678.62,7881.55]', 35 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_12', id, 'Com copart — Sênior', 'apt', 'pme', '30-99', 'comp', NULL, '[1142.25,1398.12,1750.62,1934.52,2060.51,2390.17,2857.23,3426.76,4068.37,6853.53]', 36 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_1', id, 'Sem copart — Compacto', 'enf', 'pme', '02-04', 'fac', NULL, '[568.52,695.87,871.32,962.85,1025.56,1189.63,1422.1,1705.57,2024.91,3411.14]', 37 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_2', id, 'Com copart — Compacto', 'enf', 'pme', '02-04', 'fac', NULL, '[421.13,515.46,645.42,713.22,759.67,881.21,1053.41,1263.38,1499.93,2526.77]', 38 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '02-04', 'fac', NULL, '[638.27,781.25,978.22,1080.98,1151.38,1335.58,1596.57,1914.82,2273.33,3829.63]', 39 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_4', id, 'Com copart — Efetivo', 'apt', 'pme', '02-04', 'fac', NULL, '[472.79,578.7,724.6,800.72,852.87,989.32,1182.65,1418.38,1683.95,2836.77]', 40 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_5', id, 'Sem copart — Completo', 'apt', 'pme', '02-04', 'fac', NULL, '[755.64,924.9,1158.09,1279.75,1363.1,1581.17,1890.15,2266.92,2691.36,4533.83]', 41 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_6', id, 'Com copart — Completo', 'apt', 'pme', '02-04', 'fac', NULL, '[559.73,685.11,857.85,947.96,1009.7,1171.24,1400.11,1679.2,1993.6,3358.39]', 42 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_7', id, 'Sem copart — Superior', 'apt', 'pme', '02-04', 'fac', NULL, '[836.1,1023.38,1281.4,1416.01,1508.24,1749.53,2091.41,2508.29,2977.93,5016.58]', 43 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_8', id, 'Com copart — Superior', 'apt', 'pme', '02-04', 'fac', NULL, '[668.88,818.71,1025.12,1132.81,1206.59,1399.63,1673.13,2006.63,2382.34,4013.27]', 44 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '02-04', 'fac', NULL, '[928.12,1136.02,1422.44,1571.86,1674.24,1942.09,2321.6,2784.36,3305.69,5568.72]', 45 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '02-04', 'fac', NULL, '[742.5,908.82,1137.95,1257.49,1339.39,1553.67,1857.28,2227.49,2644.55,4454.98]', 46 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_11', id, 'Sem copart — Sênior', 'apt', 'pme', '02-04', 'fac', NULL, '[1777.12,2175.2,2723.62,3009.74,3205.75,3718.63,4445.3,5331.37,6329.58,10662.75]', 47 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_12', id, 'Com copart — Sênior', 'apt', 'pme', '02-04', 'fac', NULL, '[1545.33,1891.48,2368.37,2617.16,2787.61,3233.59,3865.48,4635.98,5503.99,9271.95]', 48 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_1', id, 'Sem copart — Compacto', 'enf', 'pme', '05-29', 'fac', NULL, '[504.76,617.83,773.6,854.87,910.54,1056.22,1262.62,1514.29,1797.82,3028.58]', 49 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_2', id, 'Com copart — Compacto', 'enf', 'pme', '05-29', 'fac', NULL, '[373.9,457.65,573.04,633.24,674.48,782.38,935.27,1121.7,1331.72,2243.39]', 50 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '05-29', 'fac', NULL, '[566.69,693.63,868.51,959.75,1022.25,1185.8,1417.52,1700.07,2018.38,3400.14]', 51 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_4', id, 'Com copart — Efetivo', 'apt', 'pme', '05-29', 'fac', NULL, '[419.77,513.8,643.34,710.92,757.22,878.37,1050.01,1259.31,1495.1,2518.62]', 52 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_5', id, 'Sem copart — Completo', 'apt', 'pme', '05-29', 'fac', NULL, '[670.89,821.17,1028.21,1136.23,1210.23,1403.85,1678.17,2012.68,2389.52,4025.37]', 53 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_6', id, 'Com copart — Completo', 'apt', 'pme', '05-29', 'fac', NULL, '[496.96,608.28,761.64,841.65,896.46,1039.89,1243.09,1490.88,1770.02,2981.75]', 54 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_7', id, 'Sem copart — Superior', 'apt', 'pme', '05-29', 'fac', NULL, '[742.33,908.61,1137.69,1257.21,1339.09,1553.32,1856.86,2226.99,2643.95,4453.98]', 55 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_8', id, 'Com copart — Superior', 'apt', 'pme', '05-29', 'fac', NULL, '[593.86,726.89,910.16,1005.77,1071.27,1242.66,1485.49,1781.59,2115.16,3563.18]', 56 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '05-29', 'fac', NULL, '[824.03,1008.62,1262.91,1395.58,1486.47,1724.29,2061.23,2472.1,2934.96,4944.19]', 57 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '05-29', 'fac', NULL, '[659.23,806.89,1010.33,1116.46,1189.18,1379.43,1648.99,1977.68,2347.96,3955.35]', 58 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_11', id, 'Sem copart — Sênior', 'apt', 'pme', '05-29', 'fac', NULL, '[1577.82,1931.25,2418.17,2672.2,2846.23,3301.59,3946.76,4733.46,5619.72,9466.92]', 59 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_12', id, 'Com copart — Sênior', 'apt', 'pme', '05-29', 'fac', NULL, '[1372.02,1679.35,2102.75,2323.65,2474.98,2870.95,3431.97,4116.05,4886.72,8232.11]', 60 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_1', id, 'Sem copart — Compacto', 'enf', 'pme', '30-99', 'fac', NULL, '[462.26,565.8,708.46,782.88,833.87,967.27,1156.29,1386.77,1646.42,2773.54]', 61 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_2', id, 'Com copart — Compacto', 'enf', 'pme', '30-99', 'fac', NULL, '[342.41,419.11,524.78,579.91,617.68,716.5,856.51,1027.24,1219.57,2054.48]', 62 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '30-99', 'fac', NULL, '[518.97,635.22,795.37,878.93,936.17,1085.94,1298.15,1556.91,1848.41,3113.81]', 63 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_4', id, 'Com copart — Efetivo', 'apt', 'pme', '30-99', 'fac', NULL, '[384.42,470.53,589.16,651.06,693.46,804.4,961.59,1153.26,1369.19,2306.53]', 64 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_5', id, 'Sem copart — Completo', 'apt', 'pme', '30-99', 'fac', NULL, '[614.4,752.02,941.63,1040.54,1108.31,1285.63,1536.85,1843.19,2188.3,3686.39]', 65 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_6', id, 'Com copart — Completo', 'apt', 'pme', '30-99', 'fac', NULL, '[455.11,557.05,697.5,770.77,820.97,952.32,1138.41,1365.33,1620.96,2730.66]', 66 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_7', id, 'Sem copart — Superior', 'apt', 'pme', '30-99', 'fac', NULL, '[679.82,832.1,1041.89,1151.34,1226.32,1422.52,1700.5,2039.45,2421.31,4078.9]', 67 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_8', id, 'Com copart — Superior', 'apt', 'pme', '30-99', 'fac', NULL, '[543.85,665.68,833.51,921.07,981.06,1138.01,1360.4,1631.56,1937.04,3263.12]', 68 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '30-99', 'fac', NULL, '[754.64,923.68,1156.56,1278.06,1361.29,1579.08,1887.66,2263.92,2687.8,4527.84]', 69 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '30-99', 'fac', NULL, '[603.71,738.94,925.25,1022.45,1089.04,1263.27,1510.13,1811.14,2150.24,3622.27]', 70 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_11', id, 'Sem copart — Sênior', 'apt', 'pme', '30-99', 'fac', NULL, '[1444.95,1768.62,2214.53,2447.17,2606.55,3023.56,3614.4,4334.85,5146.48,8669.71]', 71 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_12', id, 'Com copart — Sênior', 'apt', 'pme', '30-99', 'fac', NULL, '[1256.48,1537.93,1925.68,2127.97,2266.56,2629.18,3142.96,3769.44,4475.2,7538.88]', 72 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '02-04', 'comp', NULL, '[341.65,418.18,523.61,578.61,616.3,714.9,854.6,1024.94,1216.85,2049.89]', 73 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '02-04', 'comp', NULL, '[382.3,467.94,585.92,647.47,689.64,799.97,956.29,1146.91,1361.65,2293.82]', 74 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_3', id, 'Com copart — Essencial III', 'enf', 'pme', '02-04', 'comp', NULL, '[253.07,309.76,387.86,428.6,456.52,529.55,633.03,759.22,901.37,1518.43]', 75 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '02-04', 'comp', NULL, '[283.19,346.62,434.01,479.61,510.84,592.57,708.37,849.56,1008.63,1699.13]', 76 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '05-29', 'comp', NULL, '[303.33,371.28,464.89,513.72,547.18,634.72,758.75,910.0,1080.38,1819.99]', 77 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '05-29', 'comp', NULL, '[339.43,415.46,520.21,574.86,612.29,710.25,849.05,1018.29,1208.94,2036.57]', 78 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_3', id, 'Com copart — Essencial III', 'enf', 'pme', '05-29', 'comp', NULL, '[224.69,275.02,344.36,380.54,405.32,470.16,562.04,674.07,800.28,1348.14]', 79 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '05-29', 'comp', NULL, '[251.43,307.75,385.34,425.82,453.55,526.11,628.92,754.29,895.51,1508.57]', 80 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '30-99', 'comp', NULL, '[277.79,340.01,425.74,470.46,501.1,581.27,694.86,833.36,989.4,1666.73]', 81 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '30-99', 'comp', NULL, '[310.84,380.47,476.4,526.45,560.73,650.44,777.55,932.53,1107.14,1865.07]', 82 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_3', id, 'Com copart — Essencial III', 'enf', 'pme', '30-99', 'comp', NULL, '[205.77,251.86,315.36,348.49,371.19,430.57,514.71,617.31,732.89,1234.61]', 83 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '30-99', 'comp', NULL, '[230.26,281.83,352.89,389.96,415.36,481.81,575.96,690.77,820.1,1381.53]', 84 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '02-04', 'fac', NULL, '[375.81,459.99,575.97,636.48,677.93,786.39,940.06,1127.44,1338.53,2254.87]', 85 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '02-04', 'fac', NULL, '[420.53,514.73,644.51,712.22,758.6,879.97,1051.92,1261.6,1497.82,2523.2]', 86 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_3', id, 'Com copart — Essencial III', 'enf', 'pme', '02-04', 'fac', NULL, '[278.38,340.74,426.64,471.46,502.17,582.51,696.34,835.14,991.5,1670.28]', 87 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '02-04', 'fac', NULL, '[311.51,381.28,477.42,527.57,561.93,651.83,779.2,934.52,1109.49,1869.04]', 88 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '05-29', 'fac', NULL, '[333.67,408.41,511.38,565.1,601.9,698.19,834.63,1001.0,1188.42,2001.99]', 89 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '05-29', 'fac', NULL, '[373.37,457.01,572.23,632.34,673.52,781.28,933.95,1120.11,1329.84,2240.23]', 90 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_3', id, 'Com copart — Essencial III', 'enf', 'pme', '05-29', 'fac', NULL, '[247.16,302.52,378.8,418.59,445.85,517.18,618.24,741.48,880.31,1482.96]', 91 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '05-29', 'fac', NULL, '[276.57,338.52,423.87,468.4,498.91,578.73,691.82,829.71,985.06,1659.43]', 92 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '30-99', 'fac', NULL, '[305.57,374.01,468.31,517.51,551.21,639.4,764.35,916.7,1088.34,1833.4]', 93 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '30-99', 'fac', NULL, '[341.93,418.52,524.04,579.09,616.81,715.49,855.3,1025.79,1217.85,2051.58]', 94 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_3', id, 'Com copart — Essencial III', 'enf', 'pme', '30-99', 'fac', NULL, '[226.35,277.05,346.9,383.34,408.31,473.63,566.18,679.04,806.18,1358.08]', 95 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '30-99', 'fac', NULL, '[253.28,310.02,388.18,428.96,456.89,529.99,633.56,759.84,902.11,1519.69]', 96 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 12, '[388.1,485.12,601.55,667.72,714.46,828.78,990.72,1161.13,1382.33,2328.55]', 1 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 12, '[429.21,536.51,665.27,738.45,790.15,916.58,1095.68,1284.14,1528.78,2575.22]', 2 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '03-04', NULL, 12, '[703.93,879.9,1091.07,1211.1,1295.87,1503.21,1796.94,2106.0,2507.19,4223.36]', 3 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 12, '[740.97,926.2,1148.5,1274.83,1364.07,1582.32,1891.52,2216.85,2639.15,4445.64]', 4 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 12, '[1409.78,1762.21,2185.14,2425.5,2595.27,3010.52,3598.77,4217.76,5021.24,8458.27]', 5 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 12, '[1685.85,2107.33,2613.09,2900.52,3103.54,3600.11,4303.58,5043.78,6004.62,10114.8]', 6 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 12, '[1883.16,2353.96,2918.91,3239.99,3466.79,4021.47,4807.28,5634.13,6707.43,11298.65]', 7 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '03-04', NULL, 12, '[2469.8,3087.27,3828.22,4249.33,4546.77,5274.25,6304.84,7389.25,8796.92,14818.41]', 8 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 12, '[271.67,339.58,421.08,467.41,500.13,580.14,693.51,812.79,967.64,1629.99]', 9 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 12, '[300.45,375.56,465.69,516.92,553.11,641.61,766.98,898.91,1070.14,1802.65]', 10 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '03-04', NULL, 12, '[527.94,659.92,818.31,908.32,971.9,1127.41,1347.71,1579.5,1880.4,3167.51]', 11 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 12, '[555.73,694.65,861.37,956.14,1023.06,1186.74,1418.64,1662.63,1979.37,3334.24]', 12 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 12, '[1198.3,1497.88,1857.37,2061.66,2205.99,2558.94,3058.96,3585.1,4268.06,7189.54]', 13 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 12, '[1432.98,1791.23,2221.11,2465.44,2638.01,3060.09,3658.03,4287.23,5103.93,8597.57]', 14 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 12, '[1600.69,2000.88,2481.07,2754.0,2946.78,3418.26,4086.18,4789.01,5701.31,9603.86]', 15 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '03-04', NULL, 12, '[2099.34,2624.17,3253.99,3611.93,3864.76,4483.11,5359.1,6280.87,7477.38,12595.65]', 16 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 24, '[352.81,441.01,546.85,607.02,649.51,753.43,900.66,1055.57,1256.67,2116.86]', 17 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 24, '[390.19,487.74,604.8,671.32,718.32,833.26,996.07,1167.41,1389.79,2341.11]', 18 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '03-04', NULL, 24, '[639.92,799.91,991.88,1100.99,1178.06,1366.55,1633.58,1914.55,2279.27,3839.41]', 19 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 24, '[673.61,842.01,1044.09,1158.94,1240.07,1438.48,1719.55,2015.31,2399.23,4041.49]', 20 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 24, '[1281.6,1602.01,1986.49,2205.0,2359.34,2736.83,3271.61,3834.33,4564.76,7689.35]', 21 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 24, '[1532.6,1915.74,2375.53,2636.83,2821.4,3272.83,3912.34,4585.27,5458.74,9195.27]', 22 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 24, '[1711.96,2139.97,2653.56,2945.45,3151.63,3655.89,4370.25,5121.94,6097.67,10271.51]', 23 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '03-04', NULL, 24, '[2245.28,2806.61,3480.2,3863.02,4133.42,4794.77,5731.66,6717.51,7997.19,13471.29]', 24 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 24, '[246.97,308.71,382.8,424.91,454.66,527.4,630.46,738.91,879.67,1481.81]', 25 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 24, '[273.14,341.42,423.36,469.92,502.82,583.28,697.25,817.18,972.86,1638.78]', 26 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '03-04', NULL, 24, '[479.94,599.92,743.91,825.75,883.55,1024.92,1225.18,1435.91,1709.45,2879.56]', 27 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 24, '[505.21,631.51,783.07,869.22,930.06,1078.87,1289.67,1511.49,1799.42,3031.12]', 28 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 24, '[1089.36,1361.71,1688.51,1874.24,2005.44,2326.31,2780.87,3259.18,3880.05,6535.95]', 29 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 24, '[1302.71,1628.38,2019.19,2241.31,2398.2,2781.9,3325.49,3897.48,4639.93,7815.97]', 30 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 24, '[1455.17,1818.98,2255.52,2503.63,2678.89,3107.51,3714.71,4353.64,5183.01,8730.78]', 31 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '03-04', NULL, 24, '[1908.49,2385.62,2958.17,3283.58,3513.41,4075.56,4871.92,5709.88,6797.62,11450.59]', 32 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 12, '[329.88,412.34,511.32,567.56,607.29,704.46,842.12,986.97,1174.99,1979.27]', 33 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 12, '[364.83,456.04,565.48,627.69,671.63,779.09,931.33,1091.53,1299.45,2188.94]', 34 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '05-29', NULL, 12, '[598.33,747.92,927.4,1029.43,1101.48,1277.74,1527.39,1790.1,2131.12,3589.86]', 35 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 12, '[629.82,787.28,976.21,1083.62,1159.47,1344.98,1607.79,1884.32,2243.29,3778.79]', 36 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 12, '[1198.3,1497.88,1857.37,2061.66,2205.99,2558.94,3058.96,3585.1,4268.06,7189.54]', 37 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 12, '[1432.98,1791.23,2221.11,2465.44,2638.01,3060.09,3658.03,4287.23,5103.93,8597.57]', 38 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 12, '[1600.69,2000.88,2481.07,2754.0,2946.78,3418.26,4086.18,4789.01,5701.31,9603.86]', 39 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '05-29', NULL, 12, '[2099.34,2624.17,3253.99,3611.93,3864.76,4483.11,5359.1,6280.87,7477.38,12595.65]', 40 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 12, '[230.91,288.64,357.92,397.29,425.1,493.13,589.48,690.88,822.49,1385.46]', 41 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 12, '[255.38,319.23,395.84,439.38,470.14,545.36,651.93,764.07,909.62,1532.25]', 42 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '05-29', NULL, 12, '[448.74,560.93,695.56,772.07,826.12,958.3,1145.54,1342.58,1598.34,2692.39]', 43 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 12, '[472.37,590.46,732.17,812.72,869.6,1008.73,1205.84,1413.25,1682.46,2834.1]', 44 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 12, '[1018.56,1273.2,1578.77,1752.42,1875.09,2175.09,2600.11,3047.34,3627.85,6111.11]', 45 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 12, '[1218.03,1522.54,1887.95,2095.61,2242.31,2601.09,3109.33,3644.14,4338.35,7307.94]', 46 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 12, '[1360.58,1700.74,2108.92,2340.9,2504.76,2905.52,3473.25,4070.65,4846.11,8163.29]', 47 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '05-29', NULL, 12, '[1784.43,2230.54,2765.9,3070.15,3285.04,3810.64,4555.25,5338.74,6355.78,10706.3]', 48 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 24, '[299.89,374.86,464.83,515.97,552.08,640.42,765.56,897.24,1068.17,1799.34]', 49 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 24, '[331.67,414.58,514.07,570.62,610.57,708.27,846.66,992.3,1181.32,1989.95]', 50 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '05-29', NULL, 24, '[543.95,679.91,843.1,935.85,1001.36,1161.58,1388.54,1627.36,1937.38,3263.51]', 51 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 24, '[572.56,715.71,887.47,985.1,1054.06,1222.71,1461.62,1713.01,2039.35,3435.27]', 52 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 24, '[1089.36,1361.71,1688.51,1874.24,2005.44,2326.31,2780.87,3259.18,3880.05,6535.95]', 53 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 24, '[1302.71,1628.38,2019.19,2241.31,2398.2,2781.9,3325.49,3897.48,4639.93,7815.97]', 54 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 24, '[1455.17,1818.98,2255.52,2503.63,2678.89,3107.51,3714.71,4353.64,5183.01,8730.78]', 55 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '05-29', NULL, 24, '[1908.49,2385.62,2958.17,3283.58,3513.41,4075.56,4871.92,5709.88,6797.62,11450.59]', 56 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 24, '[209.92,262.4,325.38,361.18,386.46,448.29,535.89,628.07,747.72,1259.52]', 57 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 24, '[232.17,290.21,359.86,399.44,427.4,495.79,592.67,694.6,826.93,1392.96]', 58 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '05-29', NULL, 24, '[407.95,509.94,632.32,701.88,751.01,871.18,1041.4,1220.53,1453.03,2447.63]', 59 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 24, '[429.43,536.78,665.6,738.83,790.54,917.03,1096.21,1284.77,1529.51,2576.45]', 60 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 24, '[925.96,1157.46,1435.23,1593.11,1704.62,1977.36,2363.73,2770.31,3298.05,5555.55]', 61 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 24, '[1107.29,1384.13,1716.32,1905.1,2038.46,2364.62,2826.67,3312.86,3943.95,6643.58]', 62 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 24, '[1236.9,1546.13,1917.2,2128.09,2277.06,2641.38,3157.51,3700.6,4405.57,7421.17]', 63 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '05-29', NULL, 24, '[1622.22,2027.78,2514.45,2791.04,2986.41,3464.22,4141.12,4853.39,5777.97,9733.01]', 64 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 12, '[302.29,377.86,468.55,520.09,556.49,645.53,771.67,904.4,1076.68,1813.67]', 65 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 12, '[334.32,417.9,518.2,575.2,615.46,713.94,853.44,1000.23,1190.77,2005.86]', 66 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '30-99', NULL, 12, '[549.38,686.72,851.53,945.2,1011.37,1173.19,1402.43,1643.64,1956.75,3296.15]', 67 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 12, '[578.29,722.86,896.35,994.94,1064.59,1234.93,1476.23,1730.14,2059.73,3469.62]', 68 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 12, '[1106.79,1383.49,1715.53,1904.24,2037.53,2363.54,2825.38,3311.34,3942.14,6640.54]', 69 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 12, '[1323.54,1654.43,2051.49,2277.16,2436.56,2826.41,3378.69,3959.83,4714.17,7941.02]', 70 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 12, '[1478.46,1848.08,2291.62,2543.7,2721.76,3157.24,3774.17,4423.32,5265.96,8870.51]', 71 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '30-99', NULL, 12, '[1939.03,2423.79,3005.5,3336.1,3569.64,4140.78,4949.89,5801.27,6906.4,11633.83]', 72 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 12, '[211.6,264.5,327.98,364.06,389.54,451.87,540.16,633.07,753.67,1269.56]', 73 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 12, '[234.02,292.53,362.74,402.64,430.82,499.76,597.41,700.16,833.54,1404.1]', 74 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '30-99', NULL, 12, '[412.03,515.04,638.65,708.9,758.53,879.89,1051.82,1232.73,1467.57,2472.11]', 75 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 12, '[433.71,542.14,672.25,746.2,798.44,926.19,1107.16,1297.6,1544.78,2602.19]', 76 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 12, '[940.78,1175.97,1458.2,1618.61,1731.91,2009.02,2401.58,2814.65,3350.83,5644.48]', 77 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 12, '[1125.02,1406.27,1743.77,1935.59,2071.08,2402.46,2871.9,3365.87,4007.05,6749.89]', 78 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 12, '[1256.7,1570.87,1947.88,2162.15,2313.5,2683.66,3208.05,3759.83,4476.07,7539.94]', 79 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '30-99', NULL, 12, '[1648.18,2060.22,2554.67,2835.69,3034.19,3519.66,4207.4,4931.07,5870.43,9888.75]', 80 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 24, '[299.89,374.86,464.83,515.96,552.08,640.41,765.54,897.22,1068.13,1799.27]', 81 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 24, '[331.66,414.58,514.08,570.63,610.57,708.26,846.66,992.28,1181.31,1989.92]', 82 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '30-99', NULL, 24, '[543.94,679.93,843.11,935.86,1001.37,1161.59,1388.56,1627.39,1937.41,3263.56]', 83 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 24, '[572.57,715.71,887.48,985.1,1054.06,1222.71,1461.63,1713.03,2039.36,3435.3]', 84 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 24, '[1089.36,1361.7,1688.51,1874.24,2005.44,2326.31,2780.88,3259.19,3880.06,6535.96]', 85 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 24, '[1302.7,1628.38,2019.19,2241.3,2398.2,2781.91,3325.49,3897.48,4639.94,7815.98]', 86 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 24, '[1455.18,1818.97,2255.52,2503.63,2678.89,3107.51,3714.72,4353.65,5183.01,8730.78]', 87 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '30-99', NULL, 24, '[1908.5,2385.62,2958.17,3283.57,3513.42,4075.57,4871.94,5709.91,6797.63,11450.62]', 88 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 24, '[209.93,262.41,325.39,361.18,386.46,448.3,535.9,628.07,747.72,1259.53]', 89 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 24, '[232.17,290.21,359.86,399.45,427.41,495.79,592.67,694.61,826.93,1392.96]', 90 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '30-99', NULL, 24, '[407.96,509.95,632.34,701.9,751.03,871.19,1041.42,1220.55,1453.06,2447.68]', 91 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 24, '[429.43,536.79,665.62,738.84,790.56,917.05,1096.24,1284.79,1529.54,2576.51]', 92 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 24, '[925.96,1157.45,1435.24,1593.11,1704.63,1977.38,2363.76,2770.32,3298.06,5555.59]', 93 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 24, '[1107.3,1384.12,1716.31,1905.1,2038.46,2364.62,2826.66,3312.85,3943.94,6643.57]', 94 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 24, '[1236.9,1546.13,1917.2,2128.09,2277.06,2641.39,3157.52,3700.62,4405.57,7421.19]', 95 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '30-99', NULL, 24, '[1622.22,2027.77,2514.43,2791.02,2986.4,3464.22,4141.13,4853.41,5777.97,9732.99]', 96 FROM operadoras WHERE chave='sulamerica' ON CONFLICT (codigo) DO NOTHING",
        # Etapa 5: novos campos CRM em clientes
        "ALTER TABLE clientes ADD COLUMN compartilhado INTEGER DEFAULT 0",
        "ALTER TABLE clientes ADD COLUMN plano_atual TEXT",
        "ALTER TABLE clientes ADD COLUMN operadora_atual TEXT",
        # QA: índices nas FKs do CRM
        "CREATE INDEX IF NOT EXISTS idx_clientes_corretor_id ON clientes(corretor_id)",
        "CREATE INDEX IF NOT EXISTS idx_clientes_corretora_id ON clientes(corretora_id)",
        "CREATE INDEX IF NOT EXISTS idx_oportunidades_cliente_id ON oportunidades(cliente_id)",
        "CREATE INDEX IF NOT EXISTS idx_interacoes_cliente_id ON interacoes(cliente_id)",
        "CREATE INDEX IF NOT EXISTS idx_cotacoes_cliente_id ON cotacoes(cliente_id)",
        # Fonte única de cor (HEX no banco) + chave de rede explícita por plano.
        # cor/rede_chave persistem (não há DROP); o seed só preenche quando NULL
        # ou quando há placeholder legado 'var(...)', então HEX editado no admin
        # nunca é sobrescrito por deploy.
        "ALTER TABLE operadoras ADD COLUMN cor TEXT",
        "ALTER TABLE planos ADD COLUMN rede_chave TEXT",
        "UPDATE operadoras SET cor='#0f2340' WHERE chave='unity' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#5c1a40' WHERE chave='evo' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#0a4028' WHERE chave='plenum' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#461BFF' WHERE chave='amil' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#95C13D' WHERE chave='medsenior' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#0074BE' WHERE chave='segurosunimed' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#005CB9' WHERE chave='portosaude' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#CC0000' WHERE chave='bradesco' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#1B3A8A' WHERE chave='bestsenior' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#D5531C' WHERE chave='sulamerica' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#007B40' WHERE chave='hapvida' AND (cor IS NULL OR cor LIKE 'var(%')",
        # QA: SulAmérica não possui copart parcial — só "Sem copart" e copart completa (30%).
        # Renomeia os planos "Com copart —" para "Copart Completa —" (alinha à convenção
        # Hapvida/Bradesco; o cotador então os classifica como completa, não parcial).
        # Sem LIKE/%: o wrapper passa params=() ao psycopg2, que então trata '%' como
        # placeholder e quebra. REPLACE já é seletivo (só muda quem contém 'Com copart —').
        "UPDATE planos SET nome = REPLACE(nome, 'Com copart —', 'Copart Completa —') WHERE operadora_id = (SELECT id FROM operadoras WHERE chave='sulamerica')",
        # Seguros Unimed — Coletivo por Adesão · Sem coparticipação (faixa 49-58 do documento replicada em 49-53 e 54-58)
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_1', id, 'Sem copart — Novo Essencial DF I', 'enf', 'adesao', NULL, NULL, NULL, '[325.08,399.37,498.21,550.55,586.40,680.22,813.14,975.22,975.22,1157.80]', 97 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_2', id, 'Sem copart — Novo Essencial DF II', 'apt', 'adesao', NULL, NULL, NULL, '[363.18,445.22,557.46,616.03,656.15,761.13,909.87,1091.22,1091.22,1295.52]', 98 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_3', id, 'Sem copart — Compacto', 'enf', 'adesao', NULL, NULL, NULL, '[526.76,644.75,807.31,892.12,950.21,1102.23,1317.62,1580.26,1580.26,1876.13]', 99 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_4', id, 'Sem copart — Efetivo', 'apt', 'adesao', NULL, NULL, NULL, '[589.42,721.45,903.35,998.25,1063.26,1233.38,1474.38,1768.27,1768.27,2099.99]', 100 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_5', id, 'Sem copart — Completo', 'apt', 'adesao', NULL, NULL, NULL, '[695.53,851.31,1065.94,1177.94,1254.66,1455.36,1739.78,2099.35,2099.35,2477.23]', 101 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_6', id, 'Sem copart — Superior', 'apt', 'adesao', NULL, NULL, NULL, '[829.39,1015.17,1271.10,1404.64,1496.12,1735.46,2074.60,2488.13,2488.13,2953.99]', 102 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_7', id, 'Sem copart — Superior Plus', 'apt', 'adesao', NULL, NULL, NULL, '[928.72,1136.76,1423.37,1572.90,1675.31,1943.35,2323.09,2786.15,2786.15,3307.80]', 103 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_8', id, 'Sem copart — S\xeanior', 'apt', 'adesao', NULL, NULL, NULL, '[1823.88,2232.44,2795.27,3088.94,3290.09,3816.47,4562.26,5471.64,5471.64,6496.17]', 104 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        # Seguros Unimed — Coletivo por Adesão · Com coparticipação (10 faixas no documento, sem replicação)
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_9', id, 'Com copart — Novo Essencial DF III', 'enf', 'adesao', NULL, NULL, NULL, '[283.59,347.11,434.63,480.29,511.55,593.40,709.25,850.75,1010.03,1701.48]', 105 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_10', id, 'Com copart — Novo Essencial DF IV', 'apt', 'adesao', NULL, NULL, NULL, '[317.32,388.40,486.34,537.44,572.42,664.00,793.76,951.97,1130.23,1903.91]', 106 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_11', id, 'Com copart — Compacto', 'enf', 'adesao', NULL, NULL, NULL, '[445.53,545.33,682.82,754.56,803.68,932.25,1114.44,1336.57,1586.82,2673.14]', 107 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_12', id, 'Com copart — Efetivo', 'apt', 'adesao', NULL, NULL, NULL, '[500.01,612.01,766.31,846.82,901.97,1046.28,1250.71,1500.03,1780.88,3000.04]', 108 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_13', id, 'Com copart — Completo', 'apt', 'adesao', NULL, NULL, NULL, '[594.44,727.58,911.02,1006.74,1072.31,1243.84,1486.92,1783.29,2117.19,3566.59]', 109 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_14', id, 'Com copart — Superior', 'apt', 'adesao', NULL, NULL, NULL, '[714.88,875.01,1095.61,1210.72,1289.56,1495.86,1788.17,2144.61,2546.15,4289.21]', 110 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_15', id, 'Com copart — Superior Plus', 'apt', 'adesao', NULL, NULL, NULL, '[800.50,979.82,1226.86,1355.75,1444.03,1675.06,2002.37,2401.50,2851.14,4802.99]', 111 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_16', id, 'Com copart — S\xeanior', 'apt', 'adesao', NULL, NULL, NULL, '[1649.11,2018.53,2527.42,2792.93,2974.83,3450.77,4125.09,4947.33,5873.64,9894.65]', 112 FROM operadoras WHERE chave='segurosunimed' ON CONFLICT (codigo) DO NOTHING",
        # Seguros Unimed Adesão — rede_chave próprio: Essencial e Efetivo têm rede distinta (colunas ESSENCIAL/EFETIVO_ADESAO no front). Os demais tiers caem no match por nome.
        "UPDATE planos SET rede_chave='ESSENCIAL' WHERE codigo IN ('su_ad_1','su_ad_2','su_ad_9','su_ad_10')",
        "UPDATE planos SET rede_chave='EFETIVO_ADESAO' WHERE codigo IN ('su_ad_4','su_ad_12')",
        # Fase 1 — agenda/tarefas do CRM
        "CREATE INDEX IF NOT EXISTS idx_tarefas_cliente_id ON tarefas(cliente_id)",
        "CREATE INDEX IF NOT EXISTS idx_tarefas_usuario_status_inicio ON tarefas(usuario, status, inicio)",
        # Fase Dashboard 2 — flag de gestor (vê o dashboard agregado da corretora)
        "ALTER TABLE users ADD COLUMN pode_ver_equipe INTEGER DEFAULT 0",
    ]
    for sql in safe:
        try:
            conn.execute(sql)
            conn.commit()
        except Exception:
            # psycopg2 coloca a conexão em estado "aborted" ao falhar;
            # é preciso fazer rollback para liberar a próxima migração.
            try:
                conn.rollback()
            except Exception:
                pass


def _migrations_sqlite(c):
    safe = [
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE users ADD COLUMN corretora_id INTEGER",
        "ALTER TABLE users ADD COLUMN tentativas_login INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN bloqueado_ate TEXT",
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'corretor'",
        "ALTER TABLE users ADD COLUMN session_token TEXT",
        "ALTER TABLE cotacoes ADD COLUMN corretora_id INTEGER",
        # Renomeia códigos Amil para bater com IDs de dados.js (mapeamento por preço)
        "UPDATE planos SET codigo = 'am_ad_ct_1'  WHERE codigo = 'a1'",
        "UPDATE planos SET codigo = 'am_ad_ct_2'  WHERE codigo = 'a2'",
        "UPDATE planos SET codigo = 'am_ad_ct_3'  WHERE codigo = 'a3'",
        "UPDATE planos SET codigo = 'am_ad_ct_4'  WHERE codigo = 'a4'",
        "UPDATE planos SET codigo = 'am_ad_ct_5'  WHERE codigo = 'a5'",
        "UPDATE planos SET codigo = 'am_ad_ct_6'  WHERE codigo = 'a6'",
        "UPDATE planos SET codigo = 'am_ad_ct_9'  WHERE codigo = 'a7'",
        "UPDATE planos SET codigo = 'am_ad_ct_10' WHERE codigo = 'a8'",
        "UPDATE planos SET codigo = 'am_ad_ct_7'  WHERE codigo = 'a9'",
        "UPDATE planos SET codigo = 'am_ad_ct_8'  WHERE codigo = 'a10'",
        "UPDATE planos SET codigo = 'am_ad_cp_1'  WHERE codigo = 'a11'",
        "UPDATE planos SET codigo = 'am_ad_cp_2'  WHERE codigo = 'a12'",
        "UPDATE planos SET codigo = 'am_ad_cp_3'  WHERE codigo = 'a13'",
        "UPDATE planos SET codigo = 'am_ad_cp_4'  WHERE codigo = 'a14'",
        "UPDATE planos SET codigo = 'am_ad_cp_5'  WHERE codigo = 'a15'",
        "UPDATE planos SET codigo = 'am_ad_cp_6'  WHERE codigo = 'a16'",
        "UPDATE planos SET codigo = 'am_ad_cp_9'  WHERE codigo = 'a17'",
        "UPDATE planos SET codigo = 'am_ad_cp_10' WHERE codigo = 'a18'",
        "UPDATE planos SET codigo = 'am_ad_cp_7'  WHERE codigo = 'a19'",
        "UPDATE planos SET codigo = 'am_ad_cp_8'  WHERE codigo = 'a20'",
        # Desativa planos Unity Life Vital (u1/u2) removidos do dados.js
        "UPDATE planos SET ativo = 0 WHERE codigo IN ('u1', 'u2')",
        # Rede credenciada: metadados na tabela operadoras
        "ALTER TABLE operadoras ADD COLUMN rede_adm TEXT",
        "ALTER TABLE operadoras ADD COLUMN rede_rodape TEXT",
        # Etapa 2: atualizado_em em todas as tabelas existentes
        "ALTER TABLE corretoras ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE users ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE cotacoes ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE audit_log ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE operadoras ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE planos ADD COLUMN atualizado_em TEXT",
        "ALTER TABLE rede_credenciada ADD COLUMN atualizado_em TEXT",
        # Etapa 2: FKs novas em cotacoes (SQLite: sem cláusula REFERENCES no ALTER)
        "ALTER TABLE cotacoes ADD COLUMN cliente_id INTEGER",
        "ALTER TABLE cotacoes ADD COLUMN usuario_id INTEGER",
        # Etapa 2: FK nova em audit_log
        "ALTER TABLE audit_log ADD COLUMN usuario_id INTEGER",
        # Etapa 2: índices de performance
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
        "CREATE INDEX IF NOT EXISTS idx_users_corretora_id ON users(corretora_id)",
        "CREATE INDEX IF NOT EXISTS idx_cotacoes_usuario ON cotacoes(usuario)",
        "CREATE INDEX IF NOT EXISTS idx_cotacoes_usuario_criado ON cotacoes(usuario, criado_em)",
        "CREATE INDEX IF NOT EXISTS idx_planos_operadora_id ON planos(operadora_id)",
        "CREATE INDEX IF NOT EXISTS idx_rede_operadora_id ON rede_credenciada(operadora_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_usuario ON audit_log(usuario)",
        # SQLite não suporta ALTER CONSTRAINT — CASCADE removido do CREATE TABLE para novas instalações
        # Etapa 3: renomear campos abreviados em planos (SQLite 3.25+ suporta RENAME COLUMN)
        "ALTER TABLE planos RENAME COLUMN aco TO acomodacao",
        "ALTER TABLE planos RENAME COLUMN fvidas TO faixa_vidas",
        "ALTER TABLE planos RENAME COLUMN mod TO moderador",
        "ALTER TABLE planos RENAME COLUMN vig TO mes_vigencia",
        # Etapa 3: Hapvida — inserir operadora se não existir
        "INSERT OR IGNORE INTO operadoras (chave, nome, info, ordem) VALUES ('hapvida', 'Hapvida', 'PME 2–29 vidas \xb7 Tabela Bras\xedlia \xb7 Nosso M\xe9dico e Nosso Plano \xb7 Com coparticipa\xe7\xe3o parcial ou completa \xb7 Rede credenciada DF', 11)",
        # Etapa 3: Hapvida — inserir planos (subquery garante operadora_id correto)
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cp_enf', id, 'Copart Parcial — Nosso M\xe9dico (Enf)', 'enf', 'pme', '02-29', '[147.09,164.74,184.51,212.19,244.02,290.38,362.98,453.73,771.34,863.90]', 1 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cp_apt', id, 'Copart Parcial — Nosso M\xe9dico (Apt)', 'apt', 'pme', '02-29', '[220.58,247.05,276.70,318.21,365.94,435.47,544.34,680.43,1156.73,1295.54]', 2 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cc_enf', id, 'Copart Completa — Nosso M\xe9dico (Enf)', 'enf', 'pme', '02-29', '[129.46,145.00,162.40,186.76,214.77,255.58,319.48,399.35,678.90,760.37]', 3 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_nm_cc_apt', id, 'Copart Completa — Nosso M\xe9dico (Apt)', 'apt', 'pme', '02-29', '[194.12,217.41,243.50,280.03,322.03,383.22,479.03,598.79,1017.94,1140.09]', 4 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cp_amb', id, 'Copart Parcial — Nosso Plano (Amb)', 'amb', 'pme', '02-29', '[148.42,166.23,186.18,214.11,246.23,293.01,366.26,457.83,778.31,871.71]', 5 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cp_enf', id, 'Copart Parcial — Nosso Plano (Enf)', 'enf', 'pme', '02-29', '[163.26,182.85,204.79,235.51,270.84,322.30,402.88,503.60,856.12,958.85]', 6 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cp_apt', id, 'Copart Parcial — Nosso Plano (Apt)', 'apt', 'pme', '02-29', '[244.93,274.32,307.24,353.33,406.33,483.53,604.41,755.51,1284.37,1438.40]', 7 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cc_amb', id, 'Copart Completa — Nosso Plano (Amb)', 'amb', 'pme', '02-29', '[120.72,135.21,151.44,174.16,200.28,238.33,297.91,372.39,633.06,709.03]', 8 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cc_enf', id, 'Copart Completa — Nosso Plano (Enf)', 'enf', 'pme', '02-29', '[143.68,160.92,180.23,207.26,232.35,282.64,354.55,443.19,753.48,843.83]', 9 FROM operadoras WHERE chave='hapvida'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, precos, ordem) SELECT 'hap_np_cc_apt', id, 'Copart Completa — Nosso Plano (Apt)', 'apt', 'pme', '02-29', '[215.54,241.40,270.37,310.93,357.57,425.51,531.89,664.86,1130.26,1265.89]', 10 FROM operadoras WHERE chave='hapvida'",
        # Etapa 4: 6 operadoras novas (MedSenior, Porto Saude, Best Senior, Bradesco, Seguros Unimed, SulAmerica)
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms1', id, 'Sem copart — DF3 Enfermaria', 'enf', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,803.5,964.2,1263.1]', 1 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms2', id, 'Sem copart — DF4 Apartamento', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,964.19,1157.03,1515.71]', 2 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms3', id, 'Sem copart — Black Apartamento', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1205.92,1447.1,1895.7]', 3 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms4', id, 'Sem copart — Infinite Apartamento', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1818.3,2181.96,2858.37]', 4 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms5', id, 'PME — DF Enfermaria', 'enf', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,723.14,867.77,1136.78]', 5 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms6', id, 'PME — DF Apartamento', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,867.78,1041.34,1364.16]', 6 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms7', id, 'PME — Black Apartamento', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1085.34,1302.41,1706.16]', 7 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ms8', id, 'PME — Infinite Apartamento', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,0,1487.7,1785.24,2338.66]', 8 FROM operadoras WHERE chave='medsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_1', id, 'Sem copart — Bronze Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[243.53,295.33,356.27,407.87,441.93,456.4,545.18,586.91,725.17,1218.96]', 1 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_2', id, 'Com copart — Bronze Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[187.52,227.41,274.33,314.06,340.29,351.43,419.79,451.92,558.38,938.6]', 2 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_3', id, 'Sem copart — Prata Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[287.92,349.16,421.2,482.21,522.48,539.58,644.54,693.88,857.34,1441.12]', 3 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_4', id, 'Com copart — Prata Brasília Pro', 'enf', 'pme', NULL, NULL, NULL, '[221.7,268.85,324.33,371.3,402.31,415.48,496.3,534.29,660.15,1109.66]', 4 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_5', id, 'Sem copart — P420', 'apt', 'pme', NULL, NULL, NULL, '[414.59,502.78,606.52,694.36,752.35,776.98,928.12,999.16,1234.54,2075.16]', 5 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_6', id, 'Com copart — P420', 'apt', 'pme', NULL, NULL, NULL, '[339.96,412.28,497.35,569.38,616.92,637.12,761.06,819.31,1012.32,1701.53]', 6 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_7', id, 'Sem copart — Ouro Brasília Pro', 'apt', 'pme', NULL, NULL, NULL, '[381.88,463.11,558.66,639.57,692.98,715.67,854.89,920.32,1137.13,1911.42]', 7 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'ps_8', id, 'Com copart — Ouro Brasília Pro', 'apt', 'pme', NULL, NULL, NULL, '[313.14,379.75,458.1,524.45,568.25,586.85,701.01,754.66,932.44,1567.36]', 8 FROM operadoras WHERE chave='portosaude'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf1', id, 'Sem copart — Classic (Enf)', 'enf', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,676.09,851.88,1090.4,1504.75]', 1 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf2', id, 'Sem copart — Classic (Apt)', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,829.65,1045.37,1338.07,1846.54]', 2 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf3', id, 'Sem copart — Prime (Apt)', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,982.49,1237.94,1584.56,2186.69]', 3 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pf4', id, 'Sem copart — Platinum (Apt)', 'apt', 'pf', NULL, NULL, NULL, '[0,0,0,0,0,0,1189.9,1499.28,1919.08,2648.33]', 4 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme1', id, 'Sem copart — Classic PJ (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,608.48,766.69,981.36,1353.64]', 5 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme2', id, 'Sem copart — Classic PJ (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,746.69,940.84,1204.26,1661.89]', 6 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme3', id, 'Sem copart — Prime PJ (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,884.24,1114.15,1426.1,1968.02]', 7 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bse_pme4', id, 'Sem copart — Platinum PJ (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[0,0,0,0,0,0,1070.91,1349.36,1727.17,2383.5]', 8 FROM operadoras WHERE chave='bestsenior'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_1', id, 'Sem copart — Nacional Plus 4 (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[1111.89,1312.03,1587.55,1905.08,2171.76,2236.91,2723.58,3203.48,3812.14,6670.86]', 1 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_2', id, 'Sem copart — Premium 6 (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[1535.55,1811.95,2192.44,2630.95,2999.26,3089.24,3761.34,4424.09,5264.67,9212.65]', 2 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_3', id, 'Copart total — Nacional Plus 4 (Apt)', 'apt', 'pme', NULL, NULL, NULL, '[889.51,1049.62,1270.03,1524.05,1737.4,1789.52,2178.85,2562.76,3049.68,5336.64]', 3 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_4', id, 'Sem copart — Efetivo (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[400.01,472.01,571.13,685.36,781.3,804.74,979.81,1152.46,1371.43,2399.87]', 4 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_5', id, 'Sem copart — Nacional Flex (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[466.28,550.22,665.76,798.91,910.76,938.08,1142.16,1343.41,1598.66,2797.5]', 5 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_6', id, 'Copart total — Efetivo (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[308.01,363.45,439.77,527.73,601.6,619.65,754.46,887.39,1056.0,1847.9]', 6 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'bd_7', id, 'Copart total — Nacional Flex (Enf)', 'enf', 'pme', NULL, NULL, NULL, '[359.04,423.67,512.63,615.16,701.28,722.32,879.47,1034.43,1230.97,2154.07]', 7 FROM operadoras WHERE chave='bradesco'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_1', id, 'Sem copart — Compacto', 'enf', 'pme', '02-04', 'comp', NULL, '[516.84,632.61,792.11,875.32,932.33,1081.49,1292.82,1550.52,1840.83,3101.03]', 1 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_2', id, 'Com copart — Compacto', 'enf', 'pme', '02-04', 'comp', NULL, '[382.84,468.6,586.75,648.38,690.61,801.1,957.65,1148.53,1363.57,2297.06]', 2 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '02-04', 'comp', NULL, '[580.25,710.22,889.29,982.71,1046.71,1214.17,1451.43,1740.74,2066.67,3481.49]', 3 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_4', id, 'Com copart — Efetivo', 'apt', 'pme', '02-04', 'comp', NULL, '[429.81,526.09,658.73,727.93,775.34,899.38,1075.13,1289.44,1530.86,2578.88]', 4 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_5', id, 'Sem copart — Completo', 'apt', 'pme', '02-04', 'comp', NULL, '[686.94,840.82,1052.81,1163.41,1239.18,1437.43,1718.32,2060.83,2446.69,4121.67]', 5 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_6', id, 'Com copart — Completo', 'apt', 'pme', '02-04', 'comp', NULL, '[508.85,622.83,779.86,861.78,917.91,1064.76,1272.83,1526.54,1812.36,3053.09]', 6 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_7', id, 'Sem copart — Superior', 'apt', 'pme', '02-04', 'comp', NULL, '[760.09,930.35,1164.91,1287.29,1371.12,1590.49,1901.29,2280.27,2707.21,4560.53]', 7 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_8', id, 'Com copart — Superior', 'apt', 'pme', '02-04', 'comp', NULL, '[608.07,744.28,931.93,1029.83,1096.9,1272.39,1521.03,1824.21,2165.77,3648.42]', 8 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '02-04', 'comp', NULL, '[843.75,1032.74,1293.12,1428.97,1522.03,1765.54,2110.55,2531.24,3005.17,5062.47]', 9 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '02-04', 'comp', NULL, '[675.0,826.2,1034.5,1143.17,1217.63,1412.43,1688.44,2024.99,2404.14,4049.98]', 10 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_11', id, 'Sem copart — Sênior', 'apt', 'pme', '02-04', 'comp', NULL, '[1615.57,1977.45,2476.02,2736.13,2914.32,3380.58,4041.18,4846.7,5754.17,9693.41]', 11 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c04_12', id, 'Com copart — Sênior', 'apt', 'pme', '02-04', 'comp', NULL, '[1404.84,1719.53,2153.06,2379.24,2534.19,2939.63,3514.07,4214.52,5003.62,8429.05]', 12 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_1', id, 'Sem copart — Compacto', 'enf', 'pme', '05-29', 'comp', NULL, '[458.88,561.66,703.27,777.15,827.77,960.2,1147.83,1376.63,1634.38,2753.25]', 13 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_2', id, 'Com copart — Compacto', 'enf', 'pme', '05-29', 'comp', NULL, '[339.91,416.05,520.94,575.67,613.16,711.26,850.25,1019.72,1210.65,2039.45]', 14 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '05-29', 'comp', NULL, '[515.17,630.57,789.55,872.5,929.32,1078.0,1288.65,1545.52,1834.89,3091.04]', 15 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_4', id, 'Com copart — Efetivo', 'apt', 'pme', '05-29', 'comp', NULL, '[381.61,467.09,584.85,646.29,688.39,798.52,954.56,1144.83,1359.18,2289.66]', 16 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_5', id, 'Sem copart — Completo', 'apt', 'pme', '05-29', 'comp', NULL, '[609.9,746.52,934.74,1032.93,1100.21,1276.22,1525.61,1829.71,2172.29,3659.42]', 17 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_6', id, 'Com copart — Completo', 'apt', 'pme', '05-29', 'comp', NULL, '[451.78,552.98,692.4,765.14,814.97,945.35,1130.08,1355.34,1609.11,2710.68]', 18 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_7', id, 'Sem copart — Superior', 'apt', 'pme', '05-29', 'comp', NULL, '[674.84,826.01,1034.27,1142.92,1217.35,1412.11,1688.06,2024.53,2403.6,4049.07]', 19 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_8', id, 'Com copart — Superior', 'apt', 'pme', '05-29', 'comp', NULL, '[539.88,660.81,827.41,914.33,973.88,1129.69,1350.45,1619.63,1922.88,3239.26]', 20 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '05-29', 'comp', NULL, '[749.12,916.92,1148.1,1268.71,1351.34,1567.53,1873.85,2247.36,2668.14,4494.72]', 21 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '05-29', 'comp', NULL, '[599.3,733.54,918.48,1014.97,1081.07,1254.03,1499.08,1797.89,2134.51,3595.78]', 22 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_11', id, 'Sem copart — Sênior', 'apt', 'pme', '05-29', 'comp', NULL, '[1434.38,1755.68,2198.33,2429.27,2587.48,3001.45,3587.96,4303.15,5108.84,8606.29]', 23 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c29_12', id, 'Com copart — Sênior', 'apt', 'pme', '05-29', 'comp', NULL, '[1247.29,1526.68,1911.6,2112.41,2249.98,2609.95,3119.97,3741.87,4442.47,7483.73]', 24 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_1', id, 'Sem copart — Compacto', 'enf', 'pme', '30-99', 'comp', NULL, '[420.23,514.37,644.05,711.71,758.06,879.34,1051.17,1260.7,1496.75,2521.4]', 25 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_2', id, 'Com copart — Compacto', 'enf', 'pme', '30-99', 'comp', NULL, '[311.28,381.01,477.07,527.19,561.53,651.36,778.65,933.85,1108.7,1867.71]', 26 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '30-99', 'comp', NULL, '[471.79,577.47,723.07,799.02,851.06,987.22,1180.14,1415.37,1680.37,2830.74]', 27 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_4', id, 'Com copart — Efetivo', 'apt', 'pme', '30-99', 'comp', NULL, '[349.47,427.76,535.6,591.87,630.42,731.27,874.17,1048.42,1244.72,2096.84]', 28 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_5', id, 'Sem copart — Completo', 'apt', 'pme', '30-99', 'comp', NULL, '[558.54,683.66,856.02,945.95,1007.56,1168.75,1397.14,1675.63,1989.36,3351.26]', 29 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_6', id, 'Com copart — Completo', 'apt', 'pme', '30-99', 'comp', NULL, '[413.74,506.41,634.09,700.7,746.34,865.74,1034.92,1241.21,1473.6,2482.42]', 30 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_7', id, 'Sem copart — Superior', 'apt', 'pme', '30-99', 'comp', NULL, '[618.02,756.45,947.17,1046.67,1114.84,1293.2,1545.9,1854.05,2201.19,3708.1]', 31 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_8', id, 'Com copart — Superior', 'apt', 'pme', '30-99', 'comp', NULL, '[494.41,605.16,757.74,837.34,891.87,1034.56,1236.72,1483.24,1760.95,2966.48]', 32 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '30-99', 'comp', NULL, '[686.04,839.71,1051.42,1161.87,1237.54,1435.53,1716.05,2058.11,2443.46,4116.22]', 33 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '30-99', 'comp', NULL, '[548.83,671.77,841.14,929.5,990.03,1148.42,1372.84,1646.49,1954.76,3292.97]', 34 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_11', id, 'Sem copart — Sênior', 'apt', 'pme', '30-99', 'comp', NULL, '[1313.59,1607.84,2013.21,2224.7,2369.59,2748.69,3285.82,3940.78,4678.62,7881.55]', 35 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_c99_12', id, 'Com copart — Sênior', 'apt', 'pme', '30-99', 'comp', NULL, '[1142.25,1398.12,1750.62,1934.52,2060.51,2390.17,2857.23,3426.76,4068.37,6853.53]', 36 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_1', id, 'Sem copart — Compacto', 'enf', 'pme', '02-04', 'fac', NULL, '[568.52,695.87,871.32,962.85,1025.56,1189.63,1422.1,1705.57,2024.91,3411.14]', 37 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_2', id, 'Com copart — Compacto', 'enf', 'pme', '02-04', 'fac', NULL, '[421.13,515.46,645.42,713.22,759.67,881.21,1053.41,1263.38,1499.93,2526.77]', 38 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '02-04', 'fac', NULL, '[638.27,781.25,978.22,1080.98,1151.38,1335.58,1596.57,1914.82,2273.33,3829.63]', 39 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_4', id, 'Com copart — Efetivo', 'apt', 'pme', '02-04', 'fac', NULL, '[472.79,578.7,724.6,800.72,852.87,989.32,1182.65,1418.38,1683.95,2836.77]', 40 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_5', id, 'Sem copart — Completo', 'apt', 'pme', '02-04', 'fac', NULL, '[755.64,924.9,1158.09,1279.75,1363.1,1581.17,1890.15,2266.92,2691.36,4533.83]', 41 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_6', id, 'Com copart — Completo', 'apt', 'pme', '02-04', 'fac', NULL, '[559.73,685.11,857.85,947.96,1009.7,1171.24,1400.11,1679.2,1993.6,3358.39]', 42 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_7', id, 'Sem copart — Superior', 'apt', 'pme', '02-04', 'fac', NULL, '[836.1,1023.38,1281.4,1416.01,1508.24,1749.53,2091.41,2508.29,2977.93,5016.58]', 43 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_8', id, 'Com copart — Superior', 'apt', 'pme', '02-04', 'fac', NULL, '[668.88,818.71,1025.12,1132.81,1206.59,1399.63,1673.13,2006.63,2382.34,4013.27]', 44 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '02-04', 'fac', NULL, '[928.12,1136.02,1422.44,1571.86,1674.24,1942.09,2321.6,2784.36,3305.69,5568.72]', 45 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '02-04', 'fac', NULL, '[742.5,908.82,1137.95,1257.49,1339.39,1553.67,1857.28,2227.49,2644.55,4454.98]', 46 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_11', id, 'Sem copart — Sênior', 'apt', 'pme', '02-04', 'fac', NULL, '[1777.12,2175.2,2723.62,3009.74,3205.75,3718.63,4445.3,5331.37,6329.58,10662.75]', 47 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f04_12', id, 'Com copart — Sênior', 'apt', 'pme', '02-04', 'fac', NULL, '[1545.33,1891.48,2368.37,2617.16,2787.61,3233.59,3865.48,4635.98,5503.99,9271.95]', 48 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_1', id, 'Sem copart — Compacto', 'enf', 'pme', '05-29', 'fac', NULL, '[504.76,617.83,773.6,854.87,910.54,1056.22,1262.62,1514.29,1797.82,3028.58]', 49 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_2', id, 'Com copart — Compacto', 'enf', 'pme', '05-29', 'fac', NULL, '[373.9,457.65,573.04,633.24,674.48,782.38,935.27,1121.7,1331.72,2243.39]', 50 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '05-29', 'fac', NULL, '[566.69,693.63,868.51,959.75,1022.25,1185.8,1417.52,1700.07,2018.38,3400.14]', 51 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_4', id, 'Com copart — Efetivo', 'apt', 'pme', '05-29', 'fac', NULL, '[419.77,513.8,643.34,710.92,757.22,878.37,1050.01,1259.31,1495.1,2518.62]', 52 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_5', id, 'Sem copart — Completo', 'apt', 'pme', '05-29', 'fac', NULL, '[670.89,821.17,1028.21,1136.23,1210.23,1403.85,1678.17,2012.68,2389.52,4025.37]', 53 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_6', id, 'Com copart — Completo', 'apt', 'pme', '05-29', 'fac', NULL, '[496.96,608.28,761.64,841.65,896.46,1039.89,1243.09,1490.88,1770.02,2981.75]', 54 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_7', id, 'Sem copart — Superior', 'apt', 'pme', '05-29', 'fac', NULL, '[742.33,908.61,1137.69,1257.21,1339.09,1553.32,1856.86,2226.99,2643.95,4453.98]', 55 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_8', id, 'Com copart — Superior', 'apt', 'pme', '05-29', 'fac', NULL, '[593.86,726.89,910.16,1005.77,1071.27,1242.66,1485.49,1781.59,2115.16,3563.18]', 56 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '05-29', 'fac', NULL, '[824.03,1008.62,1262.91,1395.58,1486.47,1724.29,2061.23,2472.1,2934.96,4944.19]', 57 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '05-29', 'fac', NULL, '[659.23,806.89,1010.33,1116.46,1189.18,1379.43,1648.99,1977.68,2347.96,3955.35]', 58 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_11', id, 'Sem copart — Sênior', 'apt', 'pme', '05-29', 'fac', NULL, '[1577.82,1931.25,2418.17,2672.2,2846.23,3301.59,3946.76,4733.46,5619.72,9466.92]', 59 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f29_12', id, 'Com copart — Sênior', 'apt', 'pme', '05-29', 'fac', NULL, '[1372.02,1679.35,2102.75,2323.65,2474.98,2870.95,3431.97,4116.05,4886.72,8232.11]', 60 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_1', id, 'Sem copart — Compacto', 'enf', 'pme', '30-99', 'fac', NULL, '[462.26,565.8,708.46,782.88,833.87,967.27,1156.29,1386.77,1646.42,2773.54]', 61 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_2', id, 'Com copart — Compacto', 'enf', 'pme', '30-99', 'fac', NULL, '[342.41,419.11,524.78,579.91,617.68,716.5,856.51,1027.24,1219.57,2054.48]', 62 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_3', id, 'Sem copart — Efetivo', 'apt', 'pme', '30-99', 'fac', NULL, '[518.97,635.22,795.37,878.93,936.17,1085.94,1298.15,1556.91,1848.41,3113.81]', 63 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_4', id, 'Com copart — Efetivo', 'apt', 'pme', '30-99', 'fac', NULL, '[384.42,470.53,589.16,651.06,693.46,804.4,961.59,1153.26,1369.19,2306.53]', 64 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_5', id, 'Sem copart — Completo', 'apt', 'pme', '30-99', 'fac', NULL, '[614.4,752.02,941.63,1040.54,1108.31,1285.63,1536.85,1843.19,2188.3,3686.39]', 65 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_6', id, 'Com copart — Completo', 'apt', 'pme', '30-99', 'fac', NULL, '[455.11,557.05,697.5,770.77,820.97,952.32,1138.41,1365.33,1620.96,2730.66]', 66 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_7', id, 'Sem copart — Superior', 'apt', 'pme', '30-99', 'fac', NULL, '[679.82,832.1,1041.89,1151.34,1226.32,1422.52,1700.5,2039.45,2421.31,4078.9]', 67 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_8', id, 'Com copart — Superior', 'apt', 'pme', '30-99', 'fac', NULL, '[543.85,665.68,833.51,921.07,981.06,1138.01,1360.4,1631.56,1937.04,3263.12]', 68 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_9', id, 'Sem copart — Superior Plus', 'apt', 'pme', '30-99', 'fac', NULL, '[754.64,923.68,1156.56,1278.06,1361.29,1579.08,1887.66,2263.92,2687.8,4527.84]', 69 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_10', id, 'Com copart — Superior Plus', 'apt', 'pme', '30-99', 'fac', NULL, '[603.71,738.94,925.25,1022.45,1089.04,1263.27,1510.13,1811.14,2150.24,3622.27]', 70 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_11', id, 'Sem copart — Sênior', 'apt', 'pme', '30-99', 'fac', NULL, '[1444.95,1768.62,2214.53,2447.17,2606.55,3023.56,3614.4,4334.85,5146.48,8669.71]', 71 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_f99_12', id, 'Com copart — Sênior', 'apt', 'pme', '30-99', 'fac', NULL, '[1256.48,1537.93,1925.68,2127.97,2266.56,2629.18,3142.96,3769.44,4475.2,7538.88]', 72 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '02-04', 'comp', NULL, '[341.65,418.18,523.61,578.61,616.3,714.9,854.6,1024.94,1216.85,2049.89]', 73 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '02-04', 'comp', NULL, '[382.3,467.94,585.92,647.47,689.64,799.97,956.29,1146.91,1361.65,2293.82]', 74 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_3', id, 'Com copart — Essencial III', 'enf', 'pme', '02-04', 'comp', NULL, '[253.07,309.76,387.86,428.6,456.52,529.55,633.03,759.22,901.37,1518.43]', 75 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec04_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '02-04', 'comp', NULL, '[283.19,346.62,434.01,479.61,510.84,592.57,708.37,849.56,1008.63,1699.13]', 76 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '05-29', 'comp', NULL, '[303.33,371.28,464.89,513.72,547.18,634.72,758.75,910.0,1080.38,1819.99]', 77 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '05-29', 'comp', NULL, '[339.43,415.46,520.21,574.86,612.29,710.25,849.05,1018.29,1208.94,2036.57]', 78 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_3', id, 'Com copart — Essencial III', 'enf', 'pme', '05-29', 'comp', NULL, '[224.69,275.02,344.36,380.54,405.32,470.16,562.04,674.07,800.28,1348.14]', 79 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec29_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '05-29', 'comp', NULL, '[251.43,307.75,385.34,425.82,453.55,526.11,628.92,754.29,895.51,1508.57]', 80 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '30-99', 'comp', NULL, '[277.79,340.01,425.74,470.46,501.1,581.27,694.86,833.36,989.4,1666.73]', 81 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '30-99', 'comp', NULL, '[310.84,380.47,476.4,526.45,560.73,650.44,777.55,932.53,1107.14,1865.07]', 82 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_3', id, 'Com copart — Essencial III', 'enf', 'pme', '30-99', 'comp', NULL, '[205.77,251.86,315.36,348.49,371.19,430.57,514.71,617.31,732.89,1234.61]', 83 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ec99_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '30-99', 'comp', NULL, '[230.26,281.83,352.89,389.96,415.36,481.81,575.96,690.77,820.1,1381.53]', 84 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '02-04', 'fac', NULL, '[375.81,459.99,575.97,636.48,677.93,786.39,940.06,1127.44,1338.53,2254.87]', 85 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '02-04', 'fac', NULL, '[420.53,514.73,644.51,712.22,758.6,879.97,1051.92,1261.6,1497.82,2523.2]', 86 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_3', id, 'Com copart — Essencial III', 'enf', 'pme', '02-04', 'fac', NULL, '[278.38,340.74,426.64,471.46,502.17,582.51,696.34,835.14,991.5,1670.28]', 87 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef04_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '02-04', 'fac', NULL, '[311.51,381.28,477.42,527.57,561.93,651.83,779.2,934.52,1109.49,1869.04]', 88 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '05-29', 'fac', NULL, '[333.67,408.41,511.38,565.1,601.9,698.19,834.63,1001.0,1188.42,2001.99]', 89 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '05-29', 'fac', NULL, '[373.37,457.01,572.23,632.34,673.52,781.28,933.95,1120.11,1329.84,2240.23]', 90 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_3', id, 'Com copart — Essencial III', 'enf', 'pme', '05-29', 'fac', NULL, '[247.16,302.52,378.8,418.59,445.85,517.18,618.24,741.48,880.31,1482.96]', 91 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef29_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '05-29', 'fac', NULL, '[276.57,338.52,423.87,468.4,498.91,578.73,691.82,829.71,985.06,1659.43]', 92 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_1', id, 'Sem copart — Essencial I', 'enf', 'pme', '30-99', 'fac', NULL, '[305.57,374.01,468.31,517.51,551.21,639.4,764.35,916.7,1088.34,1833.4]', 93 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_2', id, 'Sem copart — Essencial II', 'apt', 'pme', '30-99', 'fac', NULL, '[341.93,418.52,524.04,579.09,616.81,715.49,855.3,1025.79,1217.85,2051.58]', 94 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_3', id, 'Com copart — Essencial III', 'enf', 'pme', '30-99', 'fac', NULL, '[226.35,277.05,346.9,383.34,408.31,473.63,566.18,679.04,806.18,1358.08]', 95 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ef99_4', id, 'Com copart — Essencial IV', 'apt', 'pme', '30-99', 'fac', NULL, '[253.28,310.02,388.18,428.96,456.89,529.99,633.56,759.84,902.11,1519.69]', 96 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 12, '[388.1,485.12,601.55,667.72,714.46,828.78,990.72,1161.13,1382.33,2328.55]', 1 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 12, '[429.21,536.51,665.27,738.45,790.15,916.58,1095.68,1284.14,1528.78,2575.22]', 2 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '03-04', NULL, 12, '[703.93,879.9,1091.07,1211.1,1295.87,1503.21,1796.94,2106.0,2507.19,4223.36]', 3 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 12, '[740.97,926.2,1148.5,1274.83,1364.07,1582.32,1891.52,2216.85,2639.15,4445.64]', 4 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 12, '[1409.78,1762.21,2185.14,2425.5,2595.27,3010.52,3598.77,4217.76,5021.24,8458.27]', 5 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 12, '[1685.85,2107.33,2613.09,2900.52,3103.54,3600.11,4303.58,5043.78,6004.62,10114.8]', 6 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 12, '[1883.16,2353.96,2918.91,3239.99,3466.79,4021.47,4807.28,5634.13,6707.43,11298.65]', 7 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '03-04', NULL, 12, '[2469.8,3087.27,3828.22,4249.33,4546.77,5274.25,6304.84,7389.25,8796.92,14818.41]', 8 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 12, '[271.67,339.58,421.08,467.41,500.13,580.14,693.51,812.79,967.64,1629.99]', 9 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 12, '[300.45,375.56,465.69,516.92,553.11,641.61,766.98,898.91,1070.14,1802.65]', 10 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '03-04', NULL, 12, '[527.94,659.92,818.31,908.32,971.9,1127.41,1347.71,1579.5,1880.4,3167.51]', 11 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 12, '[555.73,694.65,861.37,956.14,1023.06,1186.74,1418.64,1662.63,1979.37,3334.24]', 12 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 12, '[1198.3,1497.88,1857.37,2061.66,2205.99,2558.94,3058.96,3585.1,4268.06,7189.54]', 13 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 12, '[1432.98,1791.23,2221.11,2465.44,2638.01,3060.09,3658.03,4287.23,5103.93,8597.57]', 14 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 12, '[1600.69,2000.88,2481.07,2754.0,2946.78,3418.26,4086.18,4789.01,5701.31,9603.86]', 15 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_12_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '03-04', NULL, 12, '[2099.34,2624.17,3253.99,3611.93,3864.76,4483.11,5359.1,6280.87,7477.38,12595.65]', 16 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 24, '[352.81,441.01,546.85,607.02,649.51,753.43,900.66,1055.57,1256.67,2116.86]', 17 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 24, '[390.19,487.74,604.8,671.32,718.32,833.26,996.07,1167.41,1389.79,2341.11]', 18 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '03-04', NULL, 24, '[639.92,799.91,991.88,1100.99,1178.06,1366.55,1633.58,1914.55,2279.27,3839.41]', 19 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 24, '[673.61,842.01,1044.09,1158.94,1240.07,1438.48,1719.55,2015.31,2399.23,4041.49]', 20 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 24, '[1281.6,1602.01,1986.49,2205.0,2359.34,2736.83,3271.61,3834.33,4564.76,7689.35]', 21 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 24, '[1532.6,1915.74,2375.53,2636.83,2821.4,3272.83,3912.34,4585.27,5458.74,9195.27]', 22 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 24, '[1711.96,2139.97,2653.56,2945.45,3151.63,3655.89,4370.25,5121.94,6097.67,10271.51]', 23 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '03-04', NULL, 24, '[2245.28,2806.61,3480.2,3863.02,4133.42,4794.77,5731.66,6717.51,7997.19,13471.29]', 24 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '03-04', NULL, 24, '[246.97,308.71,382.8,424.91,454.66,527.4,630.46,738.91,879.67,1481.81]', 25 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '03-04', NULL, 24, '[273.14,341.42,423.36,469.92,502.82,583.28,697.25,817.18,972.86,1638.78]', 26 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '03-04', NULL, 24, '[479.94,599.92,743.91,825.75,883.55,1024.92,1225.18,1435.91,1709.45,2879.56]', 27 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '03-04', NULL, 24, '[505.21,631.51,783.07,869.22,930.06,1078.87,1289.67,1511.49,1799.42,3031.12]', 28 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '03-04', NULL, 24, '[1089.36,1361.71,1688.51,1874.24,2005.44,2326.31,2780.87,3259.18,3880.05,6535.95]', 29 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '03-04', NULL, 24, '[1302.71,1628.38,2019.19,2241.31,2398.2,2781.9,3325.49,3897.48,4639.93,7815.97]', 30 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '03-04', NULL, 24, '[1455.17,1818.98,2255.52,2503.63,2678.89,3107.51,3714.71,4353.64,5183.01,8730.78]', 31 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_04_24_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '03-04', NULL, 24, '[1908.49,2385.62,2958.17,3283.58,3513.41,4075.56,4871.92,5709.88,6797.62,11450.59]', 32 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 12, '[329.88,412.34,511.32,567.56,607.29,704.46,842.12,986.97,1174.99,1979.27]', 33 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 12, '[364.83,456.04,565.48,627.69,671.63,779.09,931.33,1091.53,1299.45,2188.94]', 34 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '05-29', NULL, 12, '[598.33,747.92,927.4,1029.43,1101.48,1277.74,1527.39,1790.1,2131.12,3589.86]', 35 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 12, '[629.82,787.28,976.21,1083.62,1159.47,1344.98,1607.79,1884.32,2243.29,3778.79]', 36 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 12, '[1198.3,1497.88,1857.37,2061.66,2205.99,2558.94,3058.96,3585.1,4268.06,7189.54]', 37 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 12, '[1432.98,1791.23,2221.11,2465.44,2638.01,3060.09,3658.03,4287.23,5103.93,8597.57]', 38 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 12, '[1600.69,2000.88,2481.07,2754.0,2946.78,3418.26,4086.18,4789.01,5701.31,9603.86]', 39 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '05-29', NULL, 12, '[2099.34,2624.17,3253.99,3611.93,3864.76,4483.11,5359.1,6280.87,7477.38,12595.65]', 40 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 12, '[230.91,288.64,357.92,397.29,425.1,493.13,589.48,690.88,822.49,1385.46]', 41 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 12, '[255.38,319.23,395.84,439.38,470.14,545.36,651.93,764.07,909.62,1532.25]', 42 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '05-29', NULL, 12, '[448.74,560.93,695.56,772.07,826.12,958.3,1145.54,1342.58,1598.34,2692.39]', 43 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 12, '[472.37,590.46,732.17,812.72,869.6,1008.73,1205.84,1413.25,1682.46,2834.1]', 44 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 12, '[1018.56,1273.2,1578.77,1752.42,1875.09,2175.09,2600.11,3047.34,3627.85,6111.11]', 45 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 12, '[1218.03,1522.54,1887.95,2095.61,2242.31,2601.09,3109.33,3644.14,4338.35,7307.94]', 46 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 12, '[1360.58,1700.74,2108.92,2340.9,2504.76,2905.52,3473.25,4070.65,4846.11,8163.29]', 47 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_12_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '05-29', NULL, 12, '[1784.43,2230.54,2765.9,3070.15,3285.04,3810.64,4555.25,5338.74,6355.78,10706.3]', 48 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 24, '[299.89,374.86,464.83,515.97,552.08,640.42,765.56,897.24,1068.17,1799.34]', 49 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 24, '[331.67,414.58,514.07,570.62,610.57,708.27,846.66,992.3,1181.32,1989.95]', 50 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '05-29', NULL, 24, '[543.95,679.91,843.1,935.85,1001.36,1161.58,1388.54,1627.36,1937.38,3263.51]', 51 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 24, '[572.56,715.71,887.47,985.1,1054.06,1222.71,1461.62,1713.01,2039.35,3435.27]', 52 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 24, '[1089.36,1361.71,1688.51,1874.24,2005.44,2326.31,2780.87,3259.18,3880.05,6535.95]', 53 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 24, '[1302.71,1628.38,2019.19,2241.31,2398.2,2781.9,3325.49,3897.48,4639.93,7815.97]', 54 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 24, '[1455.17,1818.98,2255.52,2503.63,2678.89,3107.51,3714.71,4353.64,5183.01,8730.78]', 55 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '05-29', NULL, 24, '[1908.49,2385.62,2958.17,3283.58,3513.41,4075.56,4871.92,5709.88,6797.62,11450.59]', 56 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '05-29', NULL, 24, '[209.92,262.4,325.38,361.18,386.46,448.29,535.89,628.07,747.72,1259.52]', 57 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '05-29', NULL, 24, '[232.17,290.21,359.86,399.44,427.4,495.79,592.67,694.6,826.93,1392.96]', 58 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '05-29', NULL, 24, '[407.95,509.94,632.32,701.88,751.01,871.18,1041.4,1220.53,1453.03,2447.63]', 59 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '05-29', NULL, 24, '[429.43,536.78,665.6,738.83,790.54,917.03,1096.21,1284.77,1529.51,2576.45]', 60 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '05-29', NULL, 24, '[925.96,1157.46,1435.23,1593.11,1704.62,1977.36,2363.73,2770.31,3298.05,5555.55]', 61 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '05-29', NULL, 24, '[1107.29,1384.13,1716.32,1905.1,2038.46,2364.62,2826.67,3312.86,3943.95,6643.58]', 62 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '05-29', NULL, 24, '[1236.9,1546.13,1917.2,2128.09,2277.06,2641.38,3157.51,3700.6,4405.57,7421.17]', 63 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_29_24_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '05-29', NULL, 24, '[1622.22,2027.78,2514.45,2791.04,2986.41,3464.22,4141.12,4853.39,5777.97,9733.01]', 64 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 12, '[302.29,377.86,468.55,520.09,556.49,645.53,771.67,904.4,1076.68,1813.67]', 65 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 12, '[334.32,417.9,518.2,575.2,615.46,713.94,853.44,1000.23,1190.77,2005.86]', 66 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '30-99', NULL, 12, '[549.38,686.72,851.53,945.2,1011.37,1173.19,1402.43,1643.64,1956.75,3296.15]', 67 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 12, '[578.29,722.86,896.35,994.94,1064.59,1234.93,1476.23,1730.14,2059.73,3469.62]', 68 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 12, '[1106.79,1383.49,1715.53,1904.24,2037.53,2363.54,2825.38,3311.34,3942.14,6640.54]', 69 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 12, '[1323.54,1654.43,2051.49,2277.16,2436.56,2826.41,3378.69,3959.83,4714.17,7941.02]', 70 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 12, '[1478.46,1848.08,2291.62,2543.7,2721.76,3157.24,3774.17,4423.32,5265.96,8870.51]', 71 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '30-99', NULL, 12, '[1939.03,2423.79,3005.5,3336.1,3569.64,4140.78,4949.89,5801.27,6906.4,11633.83]', 72 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 12, '[211.6,264.5,327.98,364.06,389.54,451.87,540.16,633.07,753.67,1269.56]', 73 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 12, '[234.02,292.53,362.74,402.64,430.82,499.76,597.41,700.16,833.54,1404.1]', 74 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '30-99', NULL, 12, '[412.03,515.04,638.65,708.9,758.53,879.89,1051.82,1232.73,1467.57,2472.11]', 75 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 12, '[433.71,542.14,672.25,746.2,798.44,926.19,1107.16,1297.6,1544.78,2602.19]', 76 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 12, '[940.78,1175.97,1458.2,1618.61,1731.91,2009.02,2401.58,2814.65,3350.83,5644.48]', 77 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 12, '[1125.02,1406.27,1743.77,1935.59,2071.08,2402.46,2871.9,3365.87,4007.05,6749.89]', 78 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 12, '[1256.7,1570.87,1947.88,2162.15,2313.5,2683.66,3208.05,3759.83,4476.07,7539.94]', 79 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_12_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '30-99', NULL, 12, '[1648.18,2060.22,2554.67,2835.69,3034.19,3519.66,4207.4,4931.07,5870.43,9888.75]', 80 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_1', id, 'Sem copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 24, '[299.89,374.86,464.83,515.96,552.08,640.41,765.54,897.22,1068.13,1799.27]', 81 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_2', id, 'Sem copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 24, '[331.66,414.58,514.08,570.63,610.57,708.26,846.66,992.28,1181.31,1989.92]', 82 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_3', id, 'Sem copart — Especial RC', 'apt', 'pme', '30-99', NULL, 24, '[543.94,679.93,843.11,935.86,1001.37,1161.59,1388.56,1627.39,1937.41,3263.56]', 83 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_4', id, 'Sem copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 24, '[572.57,715.71,887.48,985.1,1054.06,1222.71,1461.63,1713.03,2039.36,3435.3]', 84 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_5', id, 'Sem copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 24, '[1089.36,1361.7,1688.51,1874.24,2005.44,2326.31,2780.88,3259.19,3880.06,6535.96]', 85 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_6', id, 'Sem copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 24, '[1302.7,1628.38,2019.19,2241.3,2398.2,2781.91,3325.49,3897.48,4639.94,7815.98]', 86 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_7', id, 'Sem copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 24, '[1455.18,1818.97,2255.52,2503.63,2678.89,3107.51,3714.72,4353.65,5183.01,8730.78]', 87 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_sc_8', id, 'Sem copart — Prestige', 'apt', 'pme', '30-99', NULL, 24, '[1908.5,2385.62,2958.17,3283.57,3513.42,4075.57,4871.94,5709.91,6797.63,11450.62]', 88 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_1', id, 'Com copart — Direto Enf', 'enf', 'pme', '30-99', NULL, 24, '[209.93,262.41,325.39,361.18,386.46,448.3,535.9,628.07,747.72,1259.53]', 89 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_2', id, 'Com copart — Direto Qto', 'apt', 'pme', '30-99', NULL, 24, '[232.17,290.21,359.86,399.45,427.41,495.79,592.67,694.61,826.93,1392.96]', 90 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_3', id, 'Com copart — Especial RC', 'apt', 'pme', '30-99', NULL, 24, '[407.96,509.95,632.34,701.9,751.03,871.19,1041.42,1220.55,1453.06,2447.68]', 91 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_4', id, 'Com copart — Especial 100 R1', 'apt', 'pme', '30-99', NULL, 24, '[429.43,536.79,665.62,738.84,790.56,917.05,1096.24,1284.79,1529.54,2576.51]', 92 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_5', id, 'Com copart — Executivo R1', 'apt', 'pme', '30-99', NULL, 24, '[925.96,1157.45,1435.24,1593.11,1704.63,1977.38,2363.76,2770.32,3298.06,5555.59]', 93 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_6', id, 'Com copart — Executivo R2', 'apt', 'pme', '30-99', NULL, 24, '[1107.3,1384.12,1716.31,1905.1,2038.46,2364.62,2826.66,3312.85,3943.94,6643.57]', 94 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_7', id, 'Com copart — Executivo R3', 'apt', 'pme', '30-99', NULL, 24, '[1236.9,1546.13,1917.2,2128.09,2277.06,2641.39,3157.52,3700.62,4405.57,7421.19]', 95 FROM operadoras WHERE chave='sulamerica'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'sa_99_24_cc_8', id, 'Com copart — Prestige', 'apt', 'pme', '30-99', NULL, 24, '[1622.22,2027.77,2514.43,2791.02,2986.4,3464.22,4141.13,4853.41,5777.97,9732.99]', 96 FROM operadoras WHERE chave='sulamerica'",
        # Etapa 5: novos campos CRM em clientes
        "ALTER TABLE clientes ADD COLUMN compartilhado INTEGER DEFAULT 0",
        "ALTER TABLE clientes ADD COLUMN plano_atual TEXT",
        "ALTER TABLE clientes ADD COLUMN operadora_atual TEXT",
        # QA: índices nas FKs do CRM
        "CREATE INDEX IF NOT EXISTS idx_clientes_corretor_id ON clientes(corretor_id)",
        "CREATE INDEX IF NOT EXISTS idx_clientes_corretora_id ON clientes(corretora_id)",
        "CREATE INDEX IF NOT EXISTS idx_oportunidades_cliente_id ON oportunidades(cliente_id)",
        "CREATE INDEX IF NOT EXISTS idx_interacoes_cliente_id ON interacoes(cliente_id)",
        "CREATE INDEX IF NOT EXISTS idx_cotacoes_cliente_id ON cotacoes(cliente_id)",
        # Fonte única de cor (HEX no banco) + chave de rede explícita por plano.
        # Seed preenche quando NULL ou placeholder 'var(...)'; não toca HEX do admin.
        "ALTER TABLE operadoras ADD COLUMN cor TEXT",
        "ALTER TABLE planos ADD COLUMN rede_chave TEXT",
        "UPDATE operadoras SET cor='#0f2340' WHERE chave='unity' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#5c1a40' WHERE chave='evo' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#0a4028' WHERE chave='plenum' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#461BFF' WHERE chave='amil' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#95C13D' WHERE chave='medsenior' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#0074BE' WHERE chave='segurosunimed' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#005CB9' WHERE chave='portosaude' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#CC0000' WHERE chave='bradesco' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#1B3A8A' WHERE chave='bestsenior' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#D5531C' WHERE chave='sulamerica' AND (cor IS NULL OR cor LIKE 'var(%')",
        "UPDATE operadoras SET cor='#007B40' WHERE chave='hapvida' AND (cor IS NULL OR cor LIKE 'var(%')",
        # QA: SulAmérica não possui copart parcial — só "Sem copart" e copart completa (30%).
        # Renomeia os planos "Com copart —" para "Copart Completa —" (alinha à convenção
        # Hapvida/Bradesco; o cotador então os classifica como completa, não parcial).
        # Sem LIKE/% por simetria com o caminho Postgres (REPLACE já é seletivo).
        "UPDATE planos SET nome = REPLACE(nome, 'Com copart —', 'Copart Completa —') WHERE operadora_id = (SELECT id FROM operadoras WHERE chave='sulamerica')",
        # Seguros Unimed — Coletivo por Adesão · Sem coparticipação (faixa 49-58 do documento replicada em 49-53 e 54-58)
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_1', id, 'Sem copart — Novo Essencial DF I', 'enf', 'adesao', NULL, NULL, NULL, '[325.08,399.37,498.21,550.55,586.40,680.22,813.14,975.22,975.22,1157.80]', 97 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_2', id, 'Sem copart — Novo Essencial DF II', 'apt', 'adesao', NULL, NULL, NULL, '[363.18,445.22,557.46,616.03,656.15,761.13,909.87,1091.22,1091.22,1295.52]', 98 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_3', id, 'Sem copart — Compacto', 'enf', 'adesao', NULL, NULL, NULL, '[526.76,644.75,807.31,892.12,950.21,1102.23,1317.62,1580.26,1580.26,1876.13]', 99 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_4', id, 'Sem copart — Efetivo', 'apt', 'adesao', NULL, NULL, NULL, '[589.42,721.45,903.35,998.25,1063.26,1233.38,1474.38,1768.27,1768.27,2099.99]', 100 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_5', id, 'Sem copart — Completo', 'apt', 'adesao', NULL, NULL, NULL, '[695.53,851.31,1065.94,1177.94,1254.66,1455.36,1739.78,2099.35,2099.35,2477.23]', 101 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_6', id, 'Sem copart — Superior', 'apt', 'adesao', NULL, NULL, NULL, '[829.39,1015.17,1271.10,1404.64,1496.12,1735.46,2074.60,2488.13,2488.13,2953.99]', 102 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_7', id, 'Sem copart — Superior Plus', 'apt', 'adesao', NULL, NULL, NULL, '[928.72,1136.76,1423.37,1572.90,1675.31,1943.35,2323.09,2786.15,2786.15,3307.80]', 103 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_8', id, 'Sem copart — S\xeanior', 'apt', 'adesao', NULL, NULL, NULL, '[1823.88,2232.44,2795.27,3088.94,3290.09,3816.47,4562.26,5471.64,5471.64,6496.17]', 104 FROM operadoras WHERE chave='segurosunimed'",
        # Seguros Unimed — Coletivo por Adesão · Com coparticipação (10 faixas no documento, sem replicação)
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_9', id, 'Com copart — Novo Essencial DF III', 'enf', 'adesao', NULL, NULL, NULL, '[283.59,347.11,434.63,480.29,511.55,593.40,709.25,850.75,1010.03,1701.48]', 105 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_10', id, 'Com copart — Novo Essencial DF IV', 'apt', 'adesao', NULL, NULL, NULL, '[317.32,388.40,486.34,537.44,572.42,664.00,793.76,951.97,1130.23,1903.91]', 106 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_11', id, 'Com copart — Compacto', 'enf', 'adesao', NULL, NULL, NULL, '[445.53,545.33,682.82,754.56,803.68,932.25,1114.44,1336.57,1586.82,2673.14]', 107 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_12', id, 'Com copart — Efetivo', 'apt', 'adesao', NULL, NULL, NULL, '[500.01,612.01,766.31,846.82,901.97,1046.28,1250.71,1500.03,1780.88,3000.04]', 108 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_13', id, 'Com copart — Completo', 'apt', 'adesao', NULL, NULL, NULL, '[594.44,727.58,911.02,1006.74,1072.31,1243.84,1486.92,1783.29,2117.19,3566.59]', 109 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_14', id, 'Com copart — Superior', 'apt', 'adesao', NULL, NULL, NULL, '[714.88,875.01,1095.61,1210.72,1289.56,1495.86,1788.17,2144.61,2546.15,4289.21]', 110 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_15', id, 'Com copart — Superior Plus', 'apt', 'adesao', NULL, NULL, NULL, '[800.50,979.82,1226.86,1355.75,1444.03,1675.06,2002.37,2401.50,2851.14,4802.99]', 111 FROM operadoras WHERE chave='segurosunimed'",
        "INSERT OR IGNORE INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) SELECT 'su_ad_16', id, 'Com copart — S\xeanior', 'apt', 'adesao', NULL, NULL, NULL, '[1649.11,2018.53,2527.42,2792.93,2974.83,3450.77,4125.09,4947.33,5873.64,9894.65]', 112 FROM operadoras WHERE chave='segurosunimed'",
        # Seguros Unimed Adesão — rede_chave próprio: Essencial e Efetivo têm rede distinta (colunas ESSENCIAL/EFETIVO_ADESAO no front). Os demais tiers caem no match por nome.
        "UPDATE planos SET rede_chave='ESSENCIAL' WHERE codigo IN ('su_ad_1','su_ad_2','su_ad_9','su_ad_10')",
        "UPDATE planos SET rede_chave='EFETIVO_ADESAO' WHERE codigo IN ('su_ad_4','su_ad_12')",
        # Fase 1 — agenda/tarefas do CRM
        "CREATE INDEX IF NOT EXISTS idx_tarefas_cliente_id ON tarefas(cliente_id)",
        "CREATE INDEX IF NOT EXISTS idx_tarefas_usuario_status_inicio ON tarefas(usuario, status, inicio)",
        # Fase Dashboard 2 — flag de gestor (vê o dashboard agregado da corretora)
        "ALTER TABLE users ADD COLUMN pode_ver_equipe INTEGER DEFAULT 0",
    ]
    for sql in safe:
        try:
            c.execute(sql)
        except Exception:
            pass


def init_db():
    conn = get_connection()

    if DATABASE_URL:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS corretoras (
                id SERIAL PRIMARY KEY,
                nome TEXT NOT NULL,
                limite_usuarios INTEGER DEFAULT 5,
                data_expiracao TEXT NOT NULL,
                ativo INTEGER DEFAULT 1,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                hashed_password TEXT NOT NULL,
                nome TEXT,
                role TEXT DEFAULT 'corretor',
                corretora_id INTEGER REFERENCES corretoras(id),
                ativo INTEGER DEFAULT 1,
                tentativas_login INTEGER DEFAULT 0,
                bloqueado_ate TEXT,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cotacoes (
                id SERIAL PRIMARY KEY,
                usuario TEXT NOT NULL,
                corretora_id INTEGER,
                cliente TEXT,
                dados TEXT,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                usuario TEXT,
                acao TEXT NOT NULL,
                detalhes TEXT,
                ip TEXT,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS operadoras (
                id SERIAL PRIMARY KEY,
                chave TEXT UNIQUE NOT NULL,
                nome TEXT NOT NULL,
                info TEXT,
                ativo INTEGER DEFAULT 1,
                ordem INTEGER DEFAULT 0,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS planos (
                id SERIAL PRIMARY KEY,
                codigo TEXT UNIQUE NOT NULL,
                operadora_id INTEGER REFERENCES operadoras(id) ON DELETE CASCADE,
                nome TEXT NOT NULL,
                acomodacao TEXT NOT NULL,
                tipo TEXT,
                faixa_vidas TEXT,
                moderador TEXT,
                mes_vigencia INTEGER,
                precos TEXT NOT NULL,
                ativo INTEGER DEFAULT 1,
                ordem INTEGER DEFAULT 0,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rede_credenciada (
                id SERIAL PRIMARY KEY,
                operadora_id INTEGER REFERENCES operadoras(id) ON DELETE CASCADE,
                grupo TEXT NOT NULL DEFAULT '',
                grupo_ordem INTEGER DEFAULT 0,
                nome TEXT NOT NULL,
                local TEXT,
                tags TEXT,
                obs TEXT,
                tag_extra TEXT,
                ordem INTEGER DEFAULT 0,
                ativo INTEGER DEFAULT 1,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clientes (
                id SERIAL PRIMARY KEY,
                nome TEXT NOT NULL,
                empresa TEXT,
                cnpj TEXT,
                telefone TEXT,
                email TEXT,
                n_vidas_estimado INTEGER,
                segmento TEXT,
                origem TEXT,
                corretor_id INTEGER REFERENCES users(id),
                corretora_id INTEGER REFERENCES corretoras(id),
                ativo INTEGER DEFAULT 1,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'),
                atualizado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oportunidades (
                id SERIAL PRIMARY KEY,
                cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
                estagio TEXT DEFAULT 'lead',
                valor_estimado REAL,
                data_prevista_fechamento TEXT,
                motivo_perda TEXT,
                obs TEXT,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'),
                atualizado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS interacoes (
                id SERIAL PRIMARY KEY,
                cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
                tipo TEXT NOT NULL,
                descricao TEXT,
                usuario TEXT REFERENCES users(username),
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'),
                atualizado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tarefas (
                id SERIAL PRIMARY KEY,
                cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
                usuario TEXT REFERENCES users(username),
                tipo TEXT NOT NULL,
                titulo TEXT NOT NULL,
                descricao TEXT,
                inicio TEXT NOT NULL,
                duracao_min INTEGER DEFAULT 30,
                status TEXT DEFAULT 'pendente',
                google_event_id TEXT,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'),
                atualizado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS integracao_google (
                usuario TEXT PRIMARY KEY REFERENCES users(username),
                refresh_token TEXT,
                google_email TEXT,
                escopo TEXT,
                criado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'),
                atualizado_em TEXT DEFAULT TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS')
            )
        """)
        conn.commit()
        _migrations_pg(conn)
    else:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS corretoras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                limite_usuarios INTEGER DEFAULT 5,
                data_expiracao TEXT NOT NULL,
                ativo INTEGER DEFAULT 1,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                hashed_password TEXT NOT NULL,
                nome TEXT,
                role TEXT DEFAULT 'corretor',
                corretora_id INTEGER,
                ativo INTEGER DEFAULT 1,
                tentativas_login INTEGER DEFAULT 0,
                bloqueado_ate TEXT,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS cotacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT NOT NULL,
                corretora_id INTEGER,
                cliente TEXT,
                dados TEXT,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT,
                acao TEXT NOT NULL,
                detalhes TEXT,
                ip TEXT,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS operadoras (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chave TEXT UNIQUE NOT NULL,
                nome TEXT NOT NULL,
                info TEXT,
                ativo INTEGER DEFAULT 1,
                ordem INTEGER DEFAULT 0,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS planos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                codigo TEXT UNIQUE NOT NULL,
                operadora_id INTEGER REFERENCES operadoras(id) ON DELETE CASCADE,
                nome TEXT NOT NULL,
                acomodacao TEXT NOT NULL,
                tipo TEXT,
                faixa_vidas TEXT,
                moderador TEXT,
                mes_vigencia INTEGER,
                precos TEXT NOT NULL,
                ativo INTEGER DEFAULT 1,
                ordem INTEGER DEFAULT 0,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rede_credenciada (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operadora_id INTEGER REFERENCES operadoras(id) ON DELETE CASCADE,
                grupo TEXT NOT NULL DEFAULT '',
                grupo_ordem INTEGER DEFAULT 0,
                nome TEXT NOT NULL,
                local TEXT,
                tags TEXT,
                obs TEXT,
                tag_extra TEXT,
                ordem INTEGER DEFAULT 0,
                ativo INTEGER DEFAULT 1,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS clientes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                empresa TEXT,
                cnpj TEXT,
                telefone TEXT,
                email TEXT,
                n_vidas_estimado INTEGER,
                segmento TEXT,
                origem TEXT,
                corretor_id INTEGER REFERENCES users(id),
                corretora_id INTEGER REFERENCES corretoras(id),
                ativo INTEGER DEFAULT 1,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
                atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS oportunidades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
                estagio TEXT DEFAULT 'lead',
                valor_estimado REAL,
                data_prevista_fechamento TEXT,
                motivo_perda TEXT,
                obs TEXT,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
                atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS interacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
                tipo TEXT NOT NULL,
                descricao TEXT,
                usuario TEXT REFERENCES users(username),
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
                atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS tarefas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
                usuario TEXT REFERENCES users(username),
                tipo TEXT NOT NULL,
                titulo TEXT NOT NULL,
                descricao TEXT,
                inicio TEXT NOT NULL,
                duracao_min INTEGER DEFAULT 30,
                status TEXT DEFAULT 'pendente',
                google_event_id TEXT,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
                atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS integracao_google (
                usuario TEXT PRIMARY KEY REFERENCES users(username),
                refresh_token TEXT,
                google_email TEXT,
                escopo TEXT,
                criado_em TEXT DEFAULT CURRENT_TIMESTAMP,
                atualizado_em TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        _migrations_sqlite(c)
        conn.commit()

    conn.close()
