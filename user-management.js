(function () {
  'use strict';

  var store = { users: [], plans: [], modules: [], audit: [], generatedAt: '', loading: false, error: '' };
  var filters = { query: '', status: '', plan: '', company: '', department: '', expiry: '', module: '' };
  var context = {};
  var ROUTE_MODULES = {
    inicio: 'tab_inicio',
    'sefaz-portal': 'tab_sefaz_portal', 'captador-notas-fiscais': 'tab_captador_notas_fiscais', 'auditor-fiscal': 'tab_auditor_fiscal', 'auditor-fiscal-nfe': 'tab_auditor_fiscal_nfe', dashboard: 'tab_dashboard', 'conttech-simples-nacional': 'tab_conttech_simples_nacional', diagnostico: 'tab_diagnostico',
    mei: 'tab_mei', 'controle-mei': 'tab_controle_mei', obrigacoes: 'tab_obrigacoes',
    'certidao-regularidade-fiscal': 'tab_certidao_regularidade_fiscal',
    'ibs-cbs': 'tab_ibs_cbs', 'transicao-reforma': 'tab_transicao_reforma', 'recuperador-pis-cofins': 'tab_recuperador_pis_cofins',
    'planejamento-tributario': 'tab_planejamento_tributario',
    'lei-complementar': 'tab_lei_complementar', 'mei-ibs-cbs': 'tab_mei_ibs_cbs',
    'parametros-2026': 'tab_parametros_2026', 'consulta-cnpj': 'tab_consulta_cnpj',
    'inscricao-estadual': 'tab_inscricao_estadual', 'cnae-servicos': 'tab_cnae_servicos',
    'ncm-tipi': 'tab_ncm_tipi', 'consulta-cest': 'tab_consulta_cest', cfop: 'tab_cfop',
    'icms-difal': 'tab_icms_difal', 'aliquotas-beneficios': 'tab_aliquotas_beneficios',
    'aliquotas-iss': 'tab_aliquotas_iss', 'emissor-nfe': 'tab_emissor_nfe', 'nfse-nacional': 'tab_nfse_nacional', 'simulador-locacao': 'tab_simulador_locacao',
    'comparativo-regimes': 'tab_comparativo_regimes',
    'nbs-cclasstrib': 'tab_nbs_cclasstrib', 'calculadora-tributaria': 'tab_calculadora_tributaria',
    'cnpj-simples': 'tab_cnpj_simples', 'analise-balanco': 'tab_analise_balanco',
    'lancamentos-contabeis': 'tab_lancamentos_contabeis', 'acompanhamento-contabil': 'tab_acompanhamento_contabil',
    'rh-dashboard': 'tab_rh_dashboard', colaboradores: 'tab_colaboradores', ferias: 'tab_ferias', afastamentos: 'tab_afastamentos', beneficios: 'tab_beneficios',
    'ponto-eletronico': 'tab_ponto_eletronico', 'banco-horas': 'tab_banco_horas', rescisoes: 'tab_rescisoes', holerite: 'tab_holerite', 'documentos-rh': 'tab_documentos_rh', folha: 'tab_folha',
    'horas-extras-noturno': 'tab_horas_extras_noturno', 'verbas-rescisorias': 'tab_verbas_rescisorias',
    'seguro-desemprego': 'tab_seguro_desemprego', 'gps-atraso': 'tab_gps_atraso',
    'pro-labore': 'tab_pro_labore', 'irrf-aliquota-efetiva': 'tab_irrf_aliquota_efetiva',
    'pensao-alimenticia': 'tab_pensao_alimenticia', 'central-calculadoras-rh': 'tab_central_calculadoras_rh', kanban: 'tab_kanban',
    'central-formularios': 'tab_central_formularios', 'modelos-contratos': 'tab_modelos_contratos',
    clientes: 'tab_clientes', 'gestao-usuarios': 'tab_gestao_usuarios',
    configuracoes: 'tab_configuracoes', historico: 'tab_historico',
    'central-suporte': 'tab_central_suporte'
  };
  var MODULE_GROUPS = [
    { label: 'Visão geral', keys: ['tab_inicio'] },
    { label: 'Área Fiscal', keys: ['tab_sefaz_portal', 'tab_captador_notas_fiscais', 'tab_auditor_fiscal', 'tab_auditor_fiscal_nfe', 'tab_dashboard', 'tab_conttech_simples_nacional', 'tab_diagnostico', 'tab_mei', 'tab_controle_mei', 'tab_obrigacoes', 'tab_certidao_regularidade_fiscal', 'tab_ibs_cbs', 'tab_transicao_reforma', 'tab_recuperador_pis_cofins', 'tab_planejamento_tributario', 'tab_lei_complementar', 'tab_mei_ibs_cbs', 'tab_parametros_2026', 'tab_consulta_cnpj', 'tab_inscricao_estadual', 'tab_cnae_servicos', 'tab_ncm_tipi', 'tab_consulta_cest', 'tab_cfop', 'tab_icms_difal', 'tab_aliquotas_beneficios', 'tab_aliquotas_iss', 'tab_emissor_nfe', 'tab_nfse_nacional', 'tab_simulador_locacao', 'tab_nbs_cclasstrib', 'tab_calculadora_tributaria', 'tab_cnpj_simples', 'tab_comparativo_regimes'] },
    { label: 'Área Contábil', keys: ['tab_analise_balanco', 'tab_lancamentos_contabeis', 'tab_acompanhamento_contabil'] },
    { label: 'RH & Departamento Pessoal', keys: ['tab_rh_dashboard', 'tab_colaboradores', 'tab_ferias', 'tab_afastamentos', 'tab_beneficios', 'tab_ponto_eletronico', 'tab_banco_horas', 'tab_rescisoes', 'tab_holerite', 'tab_documentos_rh'] },
    { label: 'Área Trabalhista', keys: ['tab_folha', 'tab_horas_extras_noturno', 'tab_verbas_rescisorias', 'tab_seguro_desemprego', 'tab_gps_atraso', 'tab_pro_labore', 'tab_irrf_aliquota_efetiva', 'tab_pensao_alimenticia', 'tab_central_calculadoras_rh'] },
    { label: 'Outros', keys: ['tab_kanban', 'tab_central_formularios', 'tab_modelos_contratos', 'tab_clientes', 'tab_gestao_usuarios', 'tab_configuracoes', 'tab_historico', 'tab_central_suporte'] }
  ];

  function esc(value) { return String(value == null ? '' : value).replace(/[&<>'"]/g, function (char) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]; }); }
  function token() { return sessionStorage.getItem('simplescalc.apiToken') || ''; }
  function profile() { try { return JSON.parse(sessionStorage.getItem('simplescalc.auth.v1') || 'null') || {}; } catch (error) { return {}; } }
  function isAdmin(user) { return String((user || profile()).role || '') === 'Administrador'; }
  function money(value) { return Number(value || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }); }
  function dateBR(value) { if (!value) return '—'; var raw = String(value).slice(0, 10).split('-'); return raw.length === 3 ? raw.reverse().join('/') : String(value); }
  function dateTimeBR(value) { if (!value) return '—'; var parsed = new Date(value); return isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString('pt-BR'); }
  function initials(name) { return String(name || 'U').split(/\s+/).slice(0, 2).map(function (part) { return part.charAt(0); }).join('').toUpperCase(); }
  function daysTo(value) { if (!value) return null; var end = new Date(String(value).slice(0, 10) + 'T12:00:00'); var now = new Date(); now.setHours(12, 0, 0, 0); return Math.ceil((end - now) / 86400000); }
  function request(path, options) {
    if (!/^https?:$/.test(location.protocol)) return Promise.reject(new Error('Abra a plataforma pelo modo seguro para usar o banco de dados e a gestão de acessos.'));
    var config = Object.assign({ headers: {} }, options || {});
    config.headers = Object.assign({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + token() }, config.headers || {});
    return fetch(path, config).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (payload) {
        if (!response.ok) throw new Error(payload.error || 'Não foi possível concluir a operação.');
        return payload;
      });
    });
  }
  function toast(title, message, type) {
    var region = document.getElementById('toast-region'); if (!region) return;
    var element = document.createElement('div'); element.className = 'toast' + (type ? ' toast--' + type : '');
    element.innerHTML = '<span>' + (type === 'error' ? '!' : type === 'warning' ? '⚠' : '✓') + '</span><div><b>' + esc(title) + '</b><span>' + esc(message || '') + '</span></div>';
    region.appendChild(element); setTimeout(function () { element.remove(); }, 4500);
  }
  function openModal(title, body, footer, wide) {
    var layer = document.getElementById('modal-layer');
    layer.innerHTML = '<section class="modal' + (wide ? ' ua-modal-wide' : '') + '" role="dialog" aria-modal="true"><header class="modal-header"><h2>' + esc(title) + '</h2><button class="icon-button" data-ua-action="close" aria-label="Fechar">×</button></header><div class="modal-body">' + body + '</div>' + (footer ? '<footer class="modal-footer">' + footer + '</footer>' : '') + '</section>';
    layer.classList.remove('is-hidden');
  }
  function closeModal() { var layer = document.getElementById('modal-layer'); if (layer) { layer.classList.add('is-hidden'); layer.innerHTML = ''; } }
  function moduleLabel(key) { var item = store.modules.find(function (module) { return module.key === key; }); return item ? item.label : key; }
  function planById(id) { return store.plans.find(function (plan) { return plan.id === id; }); }
  function planContractValue(plan, cycle) {
    if (!plan) return 0;
    if (cycle === 'Anual') return Number(plan.annualValue || 0);
    if (cycle === 'Trimestral') return Number(plan.monthlyValue || 0) * 3;
    return Number(plan.monthlyValue || 0);
  }
  function planOptionLabel(plan) {
    return plan.name + ' — ' + money(plan.monthlyValue) + '/mês · ' + money(plan.annualValue) + '/ano';
  }
  function syncPlanSubscriptionValue() {
    var form = document.getElementById('ua-user-form');
    if (!form) return;
    var planField = form.querySelector('[name="planId"]');
    var cycleField = form.querySelector('[name="billingCycle"]');
    var valueField = form.querySelector('[name="subscriptionValue"]');
    var plan = planById(planField && planField.value);
    if (valueField && plan) valueField.value = planContractValue(plan, cycleField && cycleField.value).toFixed(2);
  }
  function userById(id) { return store.users.find(function (user) { return user.id === id; }); }
  function statusClass(status) { if (status === 'Ativo') return 'success'; if (status === 'Bloqueado' || status === 'Assinatura vencida') return 'danger'; if (status === 'Aguardando ativação') return 'warning'; return 'neutral'; }
  function metric(label, value, note, tone, filterValue) { return '<button class="ua-metric ua-metric--' + (tone || 'green') + '"' + (filterValue ? ' data-ua-action="metric-filter" data-status="' + esc(filterValue) + '"' : '') + '><small>' + esc(label) + '</small><strong>' + esc(value) + '</strong><span>' + esc(note || '') + '</span></button>'; }
  function groupCount(key) {
    var counts = {};
    store.users.forEach(function (user) { var value = String(user[key] || 'Não informado'); counts[value] = (counts[value] || 0) + 1; });
    return Object.keys(counts).map(function (label) { return { label: label, value: counts[label] }; }).sort(function (a, b) { return b.value - a.value; });
  }
  function bars(items, total) {
    if (!items.length) return '<div class="ua-empty-mini">Sem dados no período.</div>';
    var max = Math.max.apply(Math, items.map(function (item) { return item.value; }).concat([1]));
    return '<div class="ua-bars">' + items.slice(0, 7).map(function (item) { return '<div><span title="' + esc(item.label) + '">' + esc(item.label) + '</span><i><b style="width:' + Math.max(5, item.value / max * 100) + '%"></b></i><strong>' + item.value + (total ? '<small> · ' + Math.round(item.value / total * 100) + '%</small>' : '') + '</strong></div>'; }).join('') + '</div>';
  }
  function subscriptionMetrics() {
    var total = store.users.length, active = 0, inactive = 0, blocked = 0, expired = 0, subscriptions = 0, d7 = 0, d15 = 0, d30 = 0;
    store.users.forEach(function (user) {
      var remaining = daysTo(user.monitoringEnd);
      if (user.status === 'Ativo') active += 1;
      if (user.status === 'Inativo') inactive += 1;
      if (user.status === 'Bloqueado') blocked += 1;
      if (user.status === 'Assinatura vencida' || (remaining != null && remaining < 0)) expired += 1;
      if (user.status === 'Ativo' && (remaining == null || remaining >= 0)) subscriptions += 1;
      if (remaining != null && remaining >= 0 && remaining <= 7) d7 += 1;
      if (remaining != null && remaining >= 0 && remaining <= 15) d15 += 1;
      if (remaining != null && remaining >= 0 && remaining <= 30) d30 += 1;
    });
    return { total: total, active: active, inactive: inactive, blocked: blocked, expired: expired, subscriptions: subscriptions, d7: d7, d15: d15, d30: d30 };
  }
  function filteredUsers() {
    return store.users.filter(function (user) {
      var haystack = [user.name, user.email, user.document, user.companyDocument, user.company, user.login].join(' ').toLowerCase();
      var remaining = daysTo(user.monitoringEnd);
      if (filters.query && haystack.indexOf(filters.query.toLowerCase()) < 0) return false;
      if (filters.status && user.status !== filters.status) return false;
      if (filters.plan && user.planId !== filters.plan) return false;
      if (filters.company && user.company !== filters.company) return false;
      if (filters.department && user.department !== filters.department) return false;
      if (filters.module && (user.modules || []).indexOf(filters.module) < 0) return false;
      if (filters.expiry && (remaining == null || remaining < 0 || remaining > Number(filters.expiry))) return false;
      return true;
    });
  }
  function optionList(items, selected, placeholder) { return '<option value="">' + esc(placeholder) + '</option>' + items.map(function (item) { return '<option value="' + esc(item) + '"' + (item === selected ? ' selected' : '') + '>' + esc(item) + '</option>'; }).join(''); }
  function renderTable() {
    var users = filteredUsers();
    var body = users.map(function (user) {
      var remaining = daysTo(user.monitoringEnd); var expiry = remaining == null ? 'Sem prazo' : remaining < 0 ? 'Vencida há ' + Math.abs(remaining) + ' dia(s)' : remaining + ' dia(s)';
      return '<tr><td><code>' + esc(String(user.id || '').slice(0, 8).toUpperCase()) + '</code></td><td><button class="ua-user-link" data-ua-action="view-user" data-id="' + esc(user.id) + '"><span>' + esc(initials(user.name)) + '</span><b>' + esc(user.name) + '</b></button></td><td><b>' + esc(user.company || '—') + '</b><small>' + esc(user.companyDocument || '') + '</small></td><td>' + esc(user.email) + '<small>@' + esc(user.login || '—') + '</small></td><td>' + esc(user.role) + '</td><td>' + esc(user.planName || 'Sem plano') + '</td><td><span class="ua-status ua-status--' + statusClass(user.status) + '">' + esc(user.status) + '</span></td><td>' + dateBR(user.monitoringStart) + '<small>até ' + dateBR(user.monitoringEnd) + ' · ' + esc(expiry) + '</small></td><td>' + dateTimeBR(user.lastLoginAt) + '</td><td><button class="ua-module-count" data-ua-action="permissions" data-id="' + esc(user.id) + '">' + (user.modules || []).length + ' módulos</button></td><td>' + dateBR(user.createdAt) + '</td><td><div class="ua-row-actions"><button data-ua-action="view-user" data-id="' + esc(user.id) + '" title="Visualizar">⌕</button><button data-ua-action="edit-user" data-id="' + esc(user.id) + '" title="Editar">✎</button><button data-ua-action="permissions" data-id="' + esc(user.id) + '" title="Permissões">⚿</button><button data-ua-action="more-user" data-id="' + esc(user.id) + '" title="Mais ações">•••</button></div></td></tr>';
    }).join('');
    return '<div class="ua-table-summary"><b>' + users.length + '</b> de ' + store.users.length + ' usuário(s) encontrados</div><div class="table-wrap ua-table-wrap"><table class="ua-table"><thead><tr><th>ID</th><th>Nome</th><th>Empresa</th><th>E-mail / login</th><th>Perfil</th><th>Plano</th><th>Status</th><th>Assinatura</th><th>Último login</th><th>Módulos</th><th>Cadastro</th><th>Ações</th></tr></thead><tbody>' + (body || '<tr><td colspan="12"><div class="empty-state"><p>Nenhum usuário corresponde aos filtros selecionados.</p></div></td></tr>') + '</tbody></table></div>';
  }
  function renderPlans() {
    return '<div class="ua-plan-grid">' + store.plans.map(function (plan) {
      var users = store.users.filter(function (user) { return user.planId === plan.id; }).length;
      return '<article class="ua-plan-card"><header><div><small>' + esc(plan.status) + '</small><h3>' + esc(plan.name) + '</h3></div><span>' + users + ' usuário(s)</span></header><p>' + esc(plan.description || 'Plano personalizável.') + '</p><div class="ua-plan-prices"><span><small>Mensal</small><b>' + money(plan.monthlyValue) + '</b></span><span><small>Anual</small><b>' + money(plan.annualValue) + '</b></span></div><div class="ua-plan-meta"><span>Até ' + esc(plan.maxUsers) + ' usuários</span><span>' + esc(plan.trialDays) + ' dias de teste</span><span>' + (plan.modules || []).length + ' módulos</span></div><footer><button class="secondary-button" data-ua-action="edit-plan" data-id="' + esc(plan.id) + '">Editar</button><button class="danger-button" data-ua-action="delete-plan" data-id="' + esc(plan.id) + '">Excluir</button></footer></article>';
    }).join('') + '</div>';
  }
  function renderAudit() {
    var rows = store.audit.slice(0, 80).map(function (item) { return '<tr><td>' + dateTimeBR(item.created_at) + '</td><td>' + esc(item.administrator_email || 'Sistema') + '</td><td>' + esc(item.affected_email || '—') + '</td><td><b>' + esc(item.action) + '</b></td><td><small>' + esc(item.previous_value || '—') + '</small></td><td><small>' + esc(item.new_value || '—') + '</small></td></tr>'; }).join('');
    return '<div class="table-wrap ua-audit-table"><table><thead><tr><th>Data e hora</th><th>Responsável</th><th>Usuário afetado</th><th>Ação</th><th>Valor anterior</th><th>Novo valor</th></tr></thead><tbody>' + (rows || '<tr><td colspan="6">Nenhuma alteração registrada.</td></tr>') + '</tbody></table></div>';
  }
  function renderContent() {
    var metrics = subscriptionMetrics();
    var statusCounts = groupCount('status'), planCounts = groupCount('planName'), companyCounts = groupCount('company'), departmentCounts = groupCount('department');
    var moduleCounts = store.modules.map(function (module) { return { label: module.label, value: store.users.filter(function (user) { return (user.modules || []).indexOf(module.key) >= 0; }).length }; }).sort(function (a, b) { return b.value - a.value; });
    var months = {}; store.users.forEach(function (user) { var month = String(user.createdAt || '').slice(0, 7) || 'Sem data'; months[month] = (months[month] || 0) + 1; });
    var monthCounts = Object.keys(months).sort().slice(-6).map(function (month) { return { label: month === 'Sem data' ? month : month.slice(5) + '/' + month.slice(0, 4), value: months[month] }; });
    var companies = Array.from(new Set(store.users.map(function (user) { return user.company; }).filter(Boolean))).sort();
    var departments = Array.from(new Set(store.users.map(function (user) { return user.department; }).filter(Boolean))).sort();
    var alert = metrics.d7 ? '<button class="ua-expiry-alert" data-ua-action="expiry-filter" data-days="7"><span>!</span><div><b>Atenção: ' + metrics.d7 + ' assinatura(s) vencem nos próximos 7 dias.</b><small>Clique para visualizar os usuários correspondentes.</small></div><strong>Ver usuários →</strong></button>' : '';
    return '<section class="ua-hero"><div><span>ADMINISTRAÇÃO E SEGURANÇA</span><h1>Gestão de Usuários e Acessos</h1><p>Controle cadastros, assinaturas, planos, permissões por módulo e auditoria em uma única área protegida.</p></div><div class="ua-hero-actions"><button class="secondary-button" data-ua-action="refresh">↻ Atualizar</button><button class="secondary-button" data-ua-action="new-plan">＋ Criar plano</button><button class="primary-button" data-ua-action="new-user">＋ Cadastrar usuário</button></div></section>' + alert +
      '<section class="ua-metrics">' + metric('Total de usuários', metrics.total, 'cadastros no banco', 'green') + metric('Usuários ativos', metrics.active, 'acesso liberado', 'success', 'Ativo') + metric('Usuários inativos', metrics.inactive, 'acesso desativado', 'neutral', 'Inativo') + metric('Usuários bloqueados', metrics.blocked, 'requer ação administrativa', 'danger', 'Bloqueado') + metric('Assinaturas ativas', metrics.subscriptions, 'vigentes no período', 'success') + metric('Assinaturas vencidas', metrics.expired, 'módulos bloqueados', 'danger', 'Assinatura vencida') + metric('Vencem em 7 dias', metrics.d7, 'alerta urgente', 'warning') + metric('Vencem em 15 / 30 dias', metrics.d15 + ' / ' + metrics.d30, 'planejamento de renovação', 'blue') + '</section>' +
      '<section class="ua-chart-grid"><article class="card"><header><h2>Usuários por status</h2></header>' + bars(statusCounts, metrics.total) + '</article><article class="card"><header><h2>Usuários por plano</h2></header>' + bars(planCounts, metrics.total) + '</article><article class="card"><header><h2>Usuários por empresa</h2></header>' + bars(companyCounts, metrics.total) + '</article><article class="card"><header><h2>Usuários por departamento</h2></header>' + bars(departmentCounts, metrics.total) + '</article><article class="card"><header><h2>Novos usuários por mês</h2></header>' + bars(monthCounts, 0) + '</article><article class="card"><header><h2>Assinaturas ativas × vencidas</h2></header>' + bars([{ label: 'Ativas', value: metrics.subscriptions }, { label: 'Vencidas', value: metrics.expired }], metrics.subscriptions + metrics.expired) + '</article><article class="card ua-chart-wide"><header><h2>Usuários por módulo liberado</h2></header>' + bars(moduleCounts, metrics.total) + '</article></section>' +
      '<section class="card ua-users-card"><header class="card-header"><div><h2>Usuários cadastrados</h2><small>Pesquisa, filtros e ações administrativas</small></div><button class="primary-button" data-ua-action="new-user">＋ Novo usuário</button></header><div class="card-body"><div class="ua-filters"><label><span>Pesquisar</span><input id="ua-query" value="' + esc(filters.query) + '" placeholder="Nome, e-mail, CPF, CNPJ ou empresa"></label><label><span>Status</span><select id="ua-status">' + optionList(['Ativo', 'Inativo', 'Bloqueado', 'Assinatura vencida', 'Aguardando ativação'], filters.status, 'Todos') + '</select></label><label><span>Plano</span><select id="ua-plan"><option value="">Todos</option>' + store.plans.map(function (plan) { return '<option value="' + esc(plan.id) + '"' + (filters.plan === plan.id ? ' selected' : '') + '>' + esc(plan.name) + '</option>'; }).join('') + '</select></label><label><span>Empresa</span><select id="ua-company">' + optionList(companies, filters.company, 'Todas') + '</select></label><label><span>Departamento</span><select id="ua-department">' + optionList(departments, filters.department, 'Todos') + '</select></label><label><span>Vencimento</span><select id="ua-expiry"><option value="">Qualquer data</option><option value="7"' + (filters.expiry === '7' ? ' selected' : '') + '>Próximos 7 dias</option><option value="15"' + (filters.expiry === '15' ? ' selected' : '') + '>Próximos 15 dias</option><option value="30"' + (filters.expiry === '30' ? ' selected' : '') + '>Próximos 30 dias</option></select></label><label><span>Módulo liberado</span><select id="ua-module"><option value="">Todos</option>' + store.modules.map(function (module) { return '<option value="' + esc(module.key) + '"' + (filters.module === module.key ? ' selected' : '') + '>' + esc(module.label) + '</option>'; }).join('') + '</select></label><button class="secondary-button" data-ua-action="clear-filters">Limpar filtros</button></div><div id="ua-table-region">' + renderTable() + '</div></div></section>' +
      '<section class="card ua-plans-section"><header class="card-header"><div><h2>Planos e Assinaturas</h2><small>Crie planos e defina módulos, valores e limites</small></div><button class="primary-button" data-ua-action="new-plan">＋ Criar plano</button></header><div class="card-body">' + renderPlans() + '</div></section>' +
      '<section class="card ua-audit-section"><header class="card-header"><div><h2>Log de auditoria</h2><small>Todas as ações administrativas registradas no banco</small></div><span class="tag tag--success">Últimos 300 eventos</span></header><div class="card-body">' + renderAudit() + '</div></section>';
  }
  function render() {
    var root = document.getElementById('user-access-management'); if (!root) return;
    if (store.loading) { root.innerHTML = '<div class="ua-loading"><span></span><b>Carregando usuários, planos e permissões…</b></div>'; return; }
    if (store.error) { root.innerHTML = '<div class="ua-backend-required"><span>🔒</span><div><h2>Banco de dados protegido necessário</h2><p>' + esc(store.error) + '</p><p>Abra <strong>ABRIR-MODO-SEGURO.cmd</strong> e acesse a plataforma pelo endereço seguro local.</p></div><button class="primary-button" data-ua-action="refresh">Tentar novamente</button></div>'; return; }
    root.innerHTML = renderContent();
  }
  function load() {
    store.loading = true; store.error = ''; render();
    return request('/api/admin/access-management').then(function (payload) { Object.assign(store, payload, { loading: false, error: '' }); if (typeof context.syncUsers === 'function') context.syncUsers(store.users); render(); }).catch(function (error) { store.loading = false; store.error = error.message; render(); });
  }
  function moduleSwitches(selected) {
    selected = selected || [];
    var modulesByKey = {};
    store.modules.forEach(function (module) { modulesByKey[module.key] = module; });
    return '<div class="ua-module-groups">' + MODULE_GROUPS.map(function (group) {
      var modules = group.keys.map(function (key) { return modulesByKey[key]; }).filter(Boolean);
      if (!modules.length) return '';
      return '<section class="ua-module-group"><header><h3>' + esc(group.label) + '</h3><small>' + modules.length + ' aba(s)</small></header><div class="ua-module-switches">' + modules.map(function (module) { return '<label><input type="checkbox" name="modules" value="' + esc(module.key) + '"' + (selected.indexOf(module.key) >= 0 ? ' checked' : '') + '><span><i></i><b>' + esc(module.label) + '</b></span></label>'; }).join('') + '</div></section>';
    }).join('') + '</div>';
  }
  function openUserForm(id, permissionsOnly) {
    var user = id ? userById(id) : null; var plan = planById(user ? user.planId : (store.plans[0] && store.plans[0].id));
    var selectedModules = user ? (user.modules || []) : ((plan && plan.modules) || []);
    var passwordRequired = !user;
    var body = '<form id="ua-user-form" data-id="' + esc(user ? user.id : '') + '"><div class="ua-form-tabs"><span>Dados cadastrais</span><span>Empresa</span><span>Assinatura</span><span>Permissões</span><span>Segurança</span></div>' +
      (permissionsOnly ? '' : '<fieldset><legend>Dados cadastrais e acesso</legend><div class="form-grid"><label class="field"><span>Nome completo *</span><input name="name" required value="' + esc(user ? user.name : '') + '"></label><label class="field"><span>E-mail *</span><input name="email" type="email" required value="' + esc(user ? user.email : '') + '"></label><label class="field"><span>CPF ou documento</span><input name="document" value="' + esc(user ? user.document : '') + '"></label><label class="field"><span>Telefone</span><input name="phone" value="' + esc(user ? user.phone : '') + '"></label><label class="field"><span>Login *</span><input name="login" required minlength="3" value="' + esc(user ? user.login : '') + '"></label><label class="field"><span>Perfil *</span><select name="role"><option' + (!user || user.role === 'Usuário' ? ' selected' : '') + '>Usuário</option><option' + (user && user.role === 'Administrador' ? ' selected' : '') + '>Administrador</option></select></label><label class="field"><span>Senha ' + (passwordRequired ? '*' : '(deixe vazia para manter)') + '</span><input name="password" type="password" minlength="8" ' + (passwordRequired ? 'required' : '') + ' autocomplete="new-password"></label><label class="field"><span>Confirmação da senha ' + (passwordRequired ? '*' : '') + '</span><input name="passwordConfirmation" type="password" minlength="8" ' + (passwordRequired ? 'required' : '') + ' autocomplete="new-password"></label></div></fieldset><fieldset><legend>Empresa e função</legend><div class="form-grid"><label class="field"><span>Empresa</span><input name="company" value="' + esc(user ? user.company : '') + '"></label><label class="field"><span>CNPJ da empresa</span><input name="companyDocument" value="' + esc(user ? user.companyDocument : '') + '"></label><label class="field"><span>Cargo</span><input name="jobTitle" value="' + esc(user ? user.jobTitle : '') + '"></label><label class="field"><span>Departamento</span><input name="department" value="' + esc(user ? user.department : '') + '"></label></div></fieldset><fieldset><legend>Plano e assinatura</legend><div class="form-grid"><label class="field"><span>Plano contratado *</span><select id="ua-user-plan" name="planId" required>' + store.plans.filter(function (item) { return item.status === 'Ativo' || (user && item.id === user.planId); }).map(function (item) { return '<option value="' + esc(item.id) + '"' + ((user ? user.planId : plan && plan.id) === item.id ? ' selected' : '') + '>' + esc(planOptionLabel(item)) + '</option>'; }).join('') + '</select></label><label class="field"><span>Periodicidade</span><select id="ua-billing-cycle" name="billingCycle"><option' + (!user || user.billingCycle === 'Mensal' ? ' selected' : '') + '>Mensal</option><option' + (user && user.billingCycle === 'Trimestral' ? ' selected' : '') + '>Trimestral</option><option' + (user && user.billingCycle === 'Anual' ? ' selected' : '') + '>Anual</option></select></label><label class="field"><span>Valor da assinatura</span><input name="subscriptionValue" type="number" min="0" step="0.01" value="' + esc(user ? user.subscriptionValue : planContractValue(plan, 'Mensal')) + '"></label><label class="field"><span>Status *</span><select name="status">' + ['Ativo', 'Inativo', 'Bloqueado', 'Assinatura vencida', 'Aguardando ativação'].map(function (status) { return '<option' + ((user ? user.status : 'Ativo') === status ? ' selected' : '') + '>' + status + '</option>'; }).join('') + '</select></label><label class="field"><span>Início da assinatura *</span><input name="monitoringStart" type="date" required value="' + esc(user ? user.monitoringStart : new Date().toISOString().slice(0, 10)) + '"></label><label class="field"><span>Vencimento da assinatura *</span><input name="monitoringEnd" type="date" required value="' + esc(user ? user.monitoringEnd : '') + '"></label><label class="field field--full"><span>Observações</span><textarea name="notes">' + esc(user ? user.notes : '') + '</textarea></label></div></fieldset>') +
      '<fieldset><legend>Permissões e Módulos Liberados</legend><div class="info-banner"><span>⚿</span><div><strong>Permissão automática + ajuste manual.</strong> Ao trocar o plano, os módulos correspondentes são marcados automaticamente. Você pode ajustar cada acesso antes de salvar.</div></div><div id="ua-module-switch-region">' + moduleSwitches(selectedModules) + '</div></fieldset></form>';
    openModal(permissionsOnly ? 'Permissões de ' + user.name : (user ? 'Editar usuário' : 'Cadastrar usuário'), body, '<button class="secondary-button" data-ua-action="close">Cancelar</button><button class="primary-button" data-ua-action="save-user">Salvar usuário e acessos</button>', true);
  }
  function userFormPayload() {
    var form = document.getElementById('ua-user-form'); var raw = Object.fromEntries(new FormData(form).entries());
    var existing = form.dataset.id ? userById(form.dataset.id) : null;
    if (existing && !raw.name) raw = Object.assign({
      name: existing.name, email: existing.email, document: existing.document, phone: existing.phone,
      company: existing.company, companyDocument: existing.companyDocument, jobTitle: existing.jobTitle,
      department: existing.department, login: existing.login, password: '', role: existing.role,
      planId: existing.planId, billingCycle: existing.billingCycle, subscriptionValue: existing.subscriptionValue,
      monitoringStart: existing.monitoringStart, monitoringEnd: existing.monitoringEnd, status: existing.status,
      notes: existing.notes
    }, raw);
    raw.modules = Array.from(form.querySelectorAll('input[name="modules"]:checked')).map(function (input) { return input.value; });
    return { form: form, data: raw };
  }
  function saveUser() {
    var result = userFormPayload(), form = result.form, data = result.data; if (!form.reportValidity()) return;
    if (data.password !== data.passwordConfirmation) { toast('Senhas diferentes', 'A senha e a confirmação precisam ser iguais.', 'error'); return; }
    if (data.monitoringEnd < data.monitoringStart) { toast('Prazo inválido', 'O vencimento não pode ser anterior ao início.', 'error'); return; }
    delete data.passwordConfirmation; var id = form.dataset.id;
    request('/api/admin/users' + (id ? '/' + id : ''), { method: id ? 'PUT' : 'POST', body: JSON.stringify(data) }).then(function (payload) { Object.assign(store, payload.data || {}); closeModal(); render(); toast(id ? 'Usuário atualizado' : 'Usuário cadastrado', 'Dados, assinatura e permissões foram gravados no banco.'); }).catch(function (error) { toast('Não foi possível salvar', error.message, 'error'); });
  }
  function openUserDetail(id) {
    var user = userById(id); if (!user) return;
    var history = store.audit.filter(function (item) { return item.affected_email === user.email; }).slice(0, 15);
    var body = '<div class="ua-profile"><header><span>' + esc(initials(user.name)) + '</span><div><h2>' + esc(user.name) + '</h2><p>' + esc(user.email) + ' · ' + esc(user.role) + '</p></div><i class="ua-status ua-status--' + statusClass(user.status) + '">' + esc(user.status) + '</i></header><div class="ua-detail-grid"><section><h3>Dados cadastrais</h3><dl><dt>Documento</dt><dd>' + esc(user.document || '—') + '</dd><dt>Telefone</dt><dd>' + esc(user.phone || '—') + '</dd><dt>Login</dt><dd>' + esc(user.login || '—') + '</dd><dt>Observações</dt><dd>' + esc(user.notes || '—') + '</dd></dl></section><section><h3>Empresa</h3><dl><dt>Empresa</dt><dd>' + esc(user.company || '—') + '</dd><dt>CNPJ</dt><dd>' + esc(user.companyDocument || '—') + '</dd><dt>Cargo</dt><dd>' + esc(user.jobTitle || '—') + '</dd><dt>Departamento</dt><dd>' + esc(user.department || '—') + '</dd></dl></section><section><h3>Assinatura</h3><dl><dt>Plano</dt><dd>' + esc(user.planName) + '</dd><dt>Período</dt><dd>' + dateBR(user.monitoringStart) + ' a ' + dateBR(user.monitoringEnd) + '</dd><dt>Valor</dt><dd>' + money(user.subscriptionValue) + ' · ' + esc(user.billingCycle) + '</dd><dt>Dias restantes</dt><dd>' + esc(user.daysRemaining == null ? 'Sem prazo' : user.daysRemaining) + '</dd></dl></section><section><h3>Segurança e acessos</h3><dl><dt>Último login</dt><dd>' + dateTimeBR(user.lastLoginAt) + '</dd><dt>IP do último acesso</dt><dd>' + esc(user.lastLoginIp || 'Não disponível') + '</dd><dt>Tentativas de login</dt><dd>' + esc(user.loginAttempts) + '</dd><dt>Bloqueado em</dt><dd>' + dateTimeBR(user.blockedAt) + '</dd></dl></section></div><section class="ua-detail-modules"><h3>Permissões</h3><div>' + (user.modules || []).map(function (key) { return '<span>' + esc(moduleLabel(key)) + '</span>'; }).join('') + '</div></section><section class="ua-detail-history"><h3>Histórico</h3>' + (history.length ? history.map(function (item) { return '<div><time>' + dateTimeBR(item.created_at) + '</time><b>' + esc(item.action) + '</b><small>Por ' + esc(item.administrator_email || 'Sistema') + '</small></div>'; }).join('') : '<p>Nenhuma alteração registrada para este usuário.</p>') + '</section><footer class="ua-created-meta">Criado por ' + esc(user.createdBy || '—') + ' em ' + dateTimeBR(user.createdAt) + ' · última alteração por ' + esc(user.updatedBy || '—') + ' em ' + dateTimeBR(user.updatedAt) + '</footer></div>';
    openModal('Perfil completo do usuário', body, '<button class="secondary-button" data-ua-action="edit-user" data-id="' + esc(user.id) + '">Editar</button><button class="secondary-button" data-ua-action="permissions" data-id="' + esc(user.id) + '">Permissões</button><button class="primary-button" data-ua-action="close">Fechar</button>', true);
  }
  function openMoreActions(id) {
    var user = userById(id); if (!user) return;
    var body = '<div class="ua-action-menu"><button data-ua-action="user-action" data-command="activate" data-id="' + esc(id) + '"><span>✓</span><b>Ativar</b><small>Liberar o acesso</small></button><button data-ua-action="user-action" data-command="inactivate" data-id="' + esc(id) + '"><span>○</span><b>Inativar</b><small>Desativar a conta</small></button><button data-ua-action="user-action" data-command="' + (user.status === 'Bloqueado' ? 'unblock' : 'block') + '" data-id="' + esc(id) + '"><span>🔒</span><b>' + (user.status === 'Bloqueado' ? 'Desbloquear' : 'Bloquear') + '</b><small>Controlar tentativas de acesso</small></button><button data-ua-action="reset-password" data-id="' + esc(id) + '"><span>⚿</span><b>Redefinir senha</b><small>Encerrar sessões anteriores</small></button><button class="danger" data-ua-action="delete-user" data-id="' + esc(id) + '"><span>×</span><b>Excluir</b><small>Remover cadastro</small></button></div>';
    openModal('Ações de ' + user.name, body, '<button class="secondary-button" data-ua-action="close">Cancelar</button>');
  }
  function runUserAction(id, command) {
    var user = userById(id); if (!user) return; if (!confirm('Confirmar a ação para “' + user.name + '”?')) return;
    request('/api/admin/users/' + id + '/action', { method: 'POST', body: JSON.stringify({ action: command }) }).then(function (payload) { Object.assign(store, payload.data || {}); closeModal(); render(); toast('Acesso atualizado', 'A ação foi registrada no histórico.'); }).catch(function (error) { toast('Ação não concluída', error.message, 'error'); });
  }
  function openPasswordReset(id) { var user = userById(id); openModal('Redefinir senha de ' + (user ? user.name : 'usuário'), '<form id="ua-password-form" data-id="' + esc(id) + '"><label class="field"><span>Nova senha *</span><input name="password" type="password" minlength="8" required autocomplete="new-password"></label><label class="field"><span>Confirmar nova senha *</span><input name="confirmation" type="password" minlength="8" required autocomplete="new-password"></label><div class="info-banner"><span>🔒</span><div>A senha será protegida por hash no banco. Todas as sessões anteriores serão encerradas.</div></div></form>', '<button class="secondary-button" data-ua-action="close">Cancelar</button><button class="primary-button" data-ua-action="save-password">Redefinir senha</button>'); }
  function savePassword() { var form = document.getElementById('ua-password-form'); if (!form.reportValidity()) return; var data = Object.fromEntries(new FormData(form).entries()); if (data.password !== data.confirmation) { toast('Senhas diferentes', 'Digite a mesma senha nos dois campos.', 'error'); return; } request('/api/admin/users/' + form.dataset.id + '/action', { method: 'POST', body: JSON.stringify({ action: 'reset_password', password: data.password }) }).then(function (payload) { Object.assign(store, payload.data || {}); closeModal(); render(); toast('Senha redefinida', 'A alteração foi registrada e as sessões antigas foram encerradas.'); }).catch(function (error) { toast('Não foi possível redefinir', error.message, 'error'); }); }
  function openPlanForm(id) {
    var plan = id ? planById(id) : null;
    var body = '<form id="ua-plan-form" data-id="' + esc(plan ? plan.id : '') + '"><div class="form-grid"><label class="field"><span>Nome do plano *</span><input name="name" required value="' + esc(plan ? plan.name : '') + '"></label><label class="field"><span>Status</span><select name="status"><option' + (!plan || plan.status === 'Ativo' ? ' selected' : '') + '>Ativo</option><option' + (plan && plan.status === 'Inativo' ? ' selected' : '') + '>Inativo</option></select></label><label class="field field--full"><span>Descrição</span><textarea name="description">' + esc(plan ? plan.description : '') + '</textarea></label><label class="field"><span>Valor mensal</span><input name="monthlyValue" type="number" min="0" step="0.01" value="' + esc(plan ? plan.monthlyValue : 0) + '"></label><label class="field"><span>Valor anual</span><input name="annualValue" type="number" min="0" step="0.01" value="' + esc(plan ? plan.annualValue : 0) + '"></label><label class="field"><span>Quantidade máxima de usuários</span><input name="maxUsers" type="number" min="1" step="1" value="' + esc(plan ? plan.maxUsers : 1) + '"></label><label class="field"><span>Período de teste (dias)</span><input name="trialDays" type="number" min="0" step="1" value="' + esc(plan ? plan.trialDays : 0) + '"></label></div><fieldset><legend>Módulos incluídos</legend>' + moduleSwitches(plan ? plan.modules : ['dashboard']) + '</fieldset></form>';
    openModal(plan ? 'Editar plano' : 'Criar plano', body, '<button class="secondary-button" data-ua-action="close">Cancelar</button><button class="primary-button" data-ua-action="save-plan">Salvar plano</button>', true);
  }
  function savePlan() { var form = document.getElementById('ua-plan-form'); if (!form.reportValidity()) return; var data = Object.fromEntries(new FormData(form).entries()); data.modules = Array.from(form.querySelectorAll('input[name="modules"]:checked')).map(function (input) { return input.value; }); var id = form.dataset.id; request('/api/admin/plans' + (id ? '/' + id : ''), { method: id ? 'PUT' : 'POST', body: JSON.stringify(data) }).then(function (payload) { Object.assign(store, payload.data || {}); closeModal(); render(); toast(id ? 'Plano atualizado' : 'Plano criado', 'Valores, limites e módulos foram gravados no banco.'); }).catch(function (error) { toast('Não foi possível salvar o plano', error.message, 'error'); }); }
  function deleteRecord(kind, id) { var record = kind === 'user' ? userById(id) : planById(id); if (!record || !confirm('Excluir “' + (record.name || record.email) + '”? Esta ação será registrada.')) return; request('/api/admin/' + (kind === 'user' ? 'users/' : 'plans/') + id, { method: 'DELETE' }).then(function (payload) { Object.assign(store, payload.data || {}); closeModal(); render(); toast(kind === 'user' ? 'Usuário excluído' : 'Plano excluído', 'O registro foi removido do banco.'); }).catch(function (error) { toast('Exclusão não concluída', error.message, 'error'); }); }
  function refreshTable() { var region = document.getElementById('ua-table-region'); if (region) region.innerHTML = renderTable(); }
  function canRoute(user, route) { if (!user) return false; if (route === 'suporte-admin') return !!user.superAdmin; if (isAdmin(user)) return true; var module = ROUTE_MODULES[route] || 'tab_inicio'; return Array.isArray(user.modules) && user.modules.indexOf(module) >= 0; }
  function applyMenu(user) {
    if (!user) return;
    document.querySelectorAll('.main-nav [data-route], .top-toolbar [data-route]').forEach(function (element) { var route = element.getAttribute('data-route'); element.hidden = route === 'gestao-usuarios' ? !isAdmin(user) : route === 'suporte-admin' ? !user.superAdmin : !canRoute(user, route); });
    document.querySelectorAll('.main-nav details').forEach(function (group) { var visible = Array.from(group.querySelectorAll('a[data-route]')).some(function (link) { return !link.hidden; }); group.hidden = !visible; });
  }
  function unauthorizedHtml() { return '<section class="ua-denied"><span>🔒</span><h1>Acesso não autorizado</h1><p>Seu usuário não possui permissão para acessar este módulo.</p><a class="primary-button" href="#inicio">Voltar ao dashboard</a></section>'; }
  function mount(root, suppliedContext) { context = suppliedContext || {}; root.innerHTML = '<div id="user-access-management"></div>'; if (!isAdmin(context.user || profile())) { document.getElementById('user-access-management').innerHTML = unauthorizedHtml(); return; } load(); }

  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-ua-action]'); if (!button) return; var action = button.dataset.uaAction, id = button.dataset.id;
    if (action === 'close') closeModal();
    else if (action === 'refresh') load();
    else if (action === 'new-user') openUserForm();
    else if (action === 'edit-user') { closeModal(); openUserForm(id); }
    else if (action === 'permissions') { closeModal(); openUserForm(id, true); }
    else if (action === 'save-user') saveUser();
    else if (action === 'view-user') openUserDetail(id);
    else if (action === 'more-user') openMoreActions(id);
    else if (action === 'user-action') runUserAction(id, button.dataset.command);
    else if (action === 'reset-password') openPasswordReset(id);
    else if (action === 'save-password') savePassword();
    else if (action === 'delete-user') deleteRecord('user', id);
    else if (action === 'new-plan') openPlanForm();
    else if (action === 'edit-plan') openPlanForm(id);
    else if (action === 'save-plan') savePlan();
    else if (action === 'delete-plan') deleteRecord('plan', id);
    else if (action === 'clear-filters') { filters = { query: '', status: '', plan: '', company: '', department: '', expiry: '', module: '' }; render(); }
    else if (action === 'metric-filter') { filters.status = button.dataset.status || ''; render(); document.querySelector('.ua-users-card').scrollIntoView({ behavior: 'smooth' }); }
    else if (action === 'expiry-filter') { filters.expiry = button.dataset.days || '7'; render(); document.querySelector('.ua-users-card').scrollIntoView({ behavior: 'smooth' }); }
  });
  document.addEventListener('change', function (event) {
    if (event.target.id === 'ua-user-plan') { var plan = planById(event.target.value); var region = document.getElementById('ua-module-switch-region'); if (plan && region) region.innerHTML = moduleSwitches(plan.modules || []); syncPlanSubscriptionValue(); }
    if (event.target.id === 'ua-billing-cycle') syncPlanSubscriptionValue();
    var map = { 'ua-status': 'status', 'ua-plan': 'plan', 'ua-company': 'company', 'ua-department': 'department', 'ua-expiry': 'expiry', 'ua-module': 'module' };
    if (map[event.target.id]) { filters[map[event.target.id]] = event.target.value; refreshTable(); }
  });
  document.addEventListener('input', function (event) { if (event.target.id === 'ua-query') { filters.query = event.target.value; clearTimeout(store.searchTimer); store.searchTimer = setTimeout(refreshTable, 100); } });

  window.UserAccessManager = { mount: mount, applyMenu: applyMenu, canRoute: canRoute, unauthorizedHtml: unauthorizedHtml, load: load, ROUTE_MODULES: ROUTE_MODULES };
})();
