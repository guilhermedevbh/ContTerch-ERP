-- Auditor Fiscal Inteligente: auditoria de documentos fiscais eletrônicos
-- (NF-e/NFC-e/CT-e/MDF-e) enviados em XML. O cliente (empresa gerenciada
-- pelo escritório) não tem tabela própria — vive no JSON de
-- app_state.payload.clients — por isso client_id não tem FK, seguindo o
-- mesmo padrão de acompanhamento_contabil/colaboradores.
--
-- itens/divergencias/resumo ficam em JSONB como snapshot: cada divergência
-- carrega sua própria decisão (pendente/aceita/rejeitada/ignorada/
-- solicitar_analise) e histórico de quem decidiu e quando, para que o
-- resultado da auditoria na data da análise não mude se as regras do
-- sistema forem atualizadas depois.

CREATE TABLE IF NOT EXISTS auditoria_fiscal_analises (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES companies(id),
  client_id TEXT,
  client_name TEXT,
  arquivo_nome TEXT NOT NULL,
  tipo_documento TEXT NOT NULL,
  modelo TEXT,
  numero TEXT,
  serie TEXT,
  chave_acesso TEXT,
  emitente_nome TEXT,
  emitente_cnpj TEXT,
  destinatario_nome TEXT,
  destinatario_cnpj TEXT,
  data_emissao TEXT,
  valor_total NUMERIC(14,2) NOT NULL DEFAULT 0,
  nivel_risco TEXT NOT NULL DEFAULT 'ok',
  risco_score INTEGER NOT NULL DEFAULT 0,
  resumo JSONB NOT NULL DEFAULT '{}',
  itens JSONB NOT NULL DEFAULT '[]',
  divergencias JSONB NOT NULL DEFAULT '[]',
  created_by TEXT,
  updated_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CONSTRAINT auditoria_fiscal_analises_nivel_check CHECK (nivel_risco IN ('ok', 'baixo', 'medio', 'alto', 'critico'))
);

CREATE INDEX IF NOT EXISTS idx_auditoria_fiscal_company ON auditoria_fiscal_analises(company_id);
CREATE INDEX IF NOT EXISTS idx_auditoria_fiscal_client ON auditoria_fiscal_analises(company_id, client_id);
