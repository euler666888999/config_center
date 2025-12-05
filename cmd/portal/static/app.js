const API_BASE = ""; // Relative to origin
const DEFAULT_ACTOR = window.DEFAULT_ACTOR || "admin";
let DEFAULT_BEARER = window.DEFAULT_BEARER || "";



// State
let state = {
    currentView: 'dashboard',
    namespaces: [],
    secrets: [],
    policies: [],
    audits: [],
    policyFilters: {
        status: '',
        search: '',
    },
    selectedNamespace: '',
    namespacesLoaded: false,
    namespacesLoading: false,
    secretsLoading: false,
    policiesLoading: false,
    auditsLoading: false,
};

// DOM Elements
const views = document.querySelectorAll('.view');
const navItems = document.querySelectorAll('.nav-item');
const pageTitle = document.getElementById('page-title');
const createBtn = document.getElementById('create-btn');

// Init
document.addEventListener('DOMContentLoaded', () => {
    console.log("App initialized");
    setupNavigation();
    setupRefresh();
    bindFilters();
    loadInitialData();
    handleRoute();
    window.addEventListener('hashchange', handleRoute);
});

function setupNavigation() {
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const target = item.dataset.target;
            if (target) {
                window.location.hash = target;
                setView(target);
            }
        });
    });
}

function setupRefresh() {
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            console.log("Manual refresh for view", state.currentView);
            refreshCurrentView(true);
        });
    }
}

function bindFilters() {
    const secretFilter = document.getElementById('secret-ns-filter');
    if (secretFilter) {
        secretFilter.addEventListener('change', (e) => {
            state.selectedNamespace = e.target.value;
            if (state.selectedNamespace) {
                loadSecrets(state.selectedNamespace);
            }
        });
    }
    const policyFilter = document.getElementById('policy-ns-filter');
    if (policyFilter) {
        policyFilter.addEventListener('change', (e) => {
            loadPolicies(e.target.value);
        });
    }
    const policyStatus = document.getElementById('policy-status-filter');
    if (policyStatus) {
        policyStatus.addEventListener('change', (e) => {
            state.policyFilters.status = e.target.value;
            renderPolicies();
        });
    }
    const policySearch = document.getElementById('policy-search');
    if (policySearch) {
        policySearch.addEventListener('input', (e) => {
            state.policyFilters.search = e.target.value.toLowerCase();
            renderPolicies();
        });
    }
    const policyRefresh = document.getElementById('policy-refresh-btn');
    if (policyRefresh) {
        policyRefresh.addEventListener('click', () => {
            const ns = policyFilter ? policyFilter.value : '';
            loadPolicies(ns, true);
        });
    }
    const auditBtn = document.getElementById('audit-query-btn');
    if (auditBtn) {
        auditBtn.addEventListener('click', () => loadAudits());
    }
}

function handleRoute() {
    const hash = window.location.hash.replace('#', '') || 'dashboard';
    setView(hash);
}

async function setView(view) {
    state.currentView = view;
    views.forEach(v => v.classList.toggle('active', v.id === `${view}-view`));
    navItems.forEach(item => item.classList.toggle('active', item.dataset.target === view));
    const titles = {
        dashboard: '概览',
        namespaces: '命名空间',
        secrets: '密钥管理',
        policies: '策略审批',
        audits: '审计日志'
    };
    pageTitle.textContent = titles[view] || '配置中心';
    if (createBtn) {
        if (view === 'namespaces') {
            createBtn.style.display = 'inline-flex';
            createBtn.onclick = showCreateNamespaceModal;
        } else if (view === 'secrets') {
            createBtn.style.display = 'inline-flex';
            createBtn.onclick = showCreateSecretModal;
        } else if (view === 'policies') {
            createBtn.style.display = 'inline-flex';
            createBtn.onclick = showCreatePolicyModal;
        } else {
            createBtn.style.display = 'none';
            createBtn.onclick = null;
        }
    }
    await refreshCurrentView();
}

async function refreshCurrentView(force = false) {
    switch (state.currentView) {
        case 'dashboard':
            await loadDashboardStats();
            break;
        case 'namespaces':
            await loadNamespaces(force);
            break;
        case 'secrets':
            await ensureNamespaces();
            const secretFilter = document.getElementById('secret-ns-filter');
            const ns = state.selectedNamespace || (secretFilter ? secretFilter.value : '');
            if (ns) {
                await loadSecrets(ns);
            }
            break;
        case 'policies':
            await ensureNamespaces();
            const policyFilter = document.getElementById('policy-ns-filter');
            await loadPolicies(policyFilter ? policyFilter.value : '');
            break;
        case 'audits':
            await loadAudits();
            break;
        default:
            break;
    }
}

// API Client
async function request(path, method = 'POST', body = null) {
    console.log(`Requesting ${method} ${path}`);
    const headers = {
        'Content-Type': 'application/json'
    };

    // CSRF
    const csrf = getCookie('PORTAL_CSRF');
    if (csrf) headers['X-CSRF-Token'] = csrf;

    // Token / Actor
    const token = localStorage.getItem('token') || DEFAULT_BEARER;
    if (token) {
        headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`;
    } else {
        // Warn but proceed, relying on cookie-based auth
        console.warn("未找到 Authorization Bearer，尝试使用 Cookie 认证");
    }

    const actor = localStorage.getItem('actor') || DEFAULT_ACTOR;
    if (actor) headers['X-Actor'] = actor;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    try {
        console.log("Fetching...", opts);
        const res = await fetch(API_BASE + path, opts);
        console.log(`Response status: ${res.status}`);
        if (res.status === 401) {
            // Handle login if needed, for now just alert
            console.error("Unauthorized");
        }
        if (!res.ok) {
            const txt = await res.text();
            throw new Error(txt || res.statusText);
        }
        return await res.json();
    } catch (e) {
        console.error("API Error:", e);
        alert("错误: " + e.message);
        throw e;
    }
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return decodeURIComponent(parts.pop().split(';').shift());
}

// Data Loading
async function loadInitialData() {
    console.log("Loading initial data");
    await loadNamespaces();
}

async function ensureNamespaces() {
    if (!state.namespacesLoaded) {
        await loadNamespaces(true);
    }
}

async function loadNamespaces(force = false) {
    console.log("loadNamespaces called", { force, loading: state.namespacesLoading, loaded: state.namespacesLoaded });
    if (state.namespacesLoading) return state.namespaces;
    if (state.namespacesLoaded && !force) return state.namespaces;
    state.namespacesLoading = true;
    try {
        const res = await request('/v1/admin/namespaces', 'POST', { action: 'list' });
        state.namespaces = res.items || [];
        state.namespacesLoaded = true;
        renderNamespaces();
        updateNamespaceSelects();
    } catch (e) {
        // Fallback if admin API fails (user might not be admin)
        console.warn("Failed to load namespaces via admin API", e);
    } finally {
        state.namespacesLoading = false;
    }
}

async function loadSecrets(ns) {
    if (state.secretsLoading) return;
    state.secretsLoading = true;
    try {
        const res = await request(`/v1/namespaces/${ns}/secrets`, 'POST', { action: 'list' });
        state.secrets = res.secrets || [];
        renderSecrets();
    } finally {
        state.secretsLoading = false;
    }
}

async function loadPolicies(ns, force = false) {
    if (state.policiesLoading && !force) return;
    state.policiesLoading = true;
    try {
        const body = { action: 'list' };
        if (ns) body.namespace = ns;
        const res = await request('/v1/authz/policies', 'POST', body);
        state.policies = Array.isArray(res) ? res : (res.items || []);
        renderPolicies();
    } finally {
        state.policiesLoading = false;
    }
}

async function loadAudits() {
    if (state.auditsLoading) return;
    state.auditsLoading = true;
    try {
        const ns = document.getElementById('audit-ns').value;
        const name = document.getElementById('audit-name').value;
        const res = await request('/proxy/audit', 'POST', {
            namespace: ns,
            name: name,
            page_size: 20
        });
        state.audits = res.items || [];
        renderAudits();
    } finally {
        state.auditsLoading = false;
    }
}

async function loadDashboardStats() {
    if (!state.namespacesLoaded && !state.namespacesLoading) {
        await loadNamespaces();
    }
    document.getElementById('stat-namespaces').textContent = state.namespaces.length;
    // Mock other stats for now as we don't have global counters API
    document.getElementById('stat-secrets').textContent = '-';
    document.getElementById('stat-approvals').textContent = '-';
}

// Rendering
function renderNamespaces() {
    const tbody = document.getElementById('namespaces-list');
    tbody.innerHTML = state.namespaces.map(ns => `
        <tr>
            <td><strong>${ns}</strong></td>
            <td>-</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="viewNamespaceSecrets('${ns}')">查看密钥</button>
            </td>
        </tr>
    `).join('');
}

function updateNamespaceSelects() {
    const opts = `<option value="">选择命名空间...</option>` +
        state.namespaces.map(ns => `<option value="${ns}">${ns}</option>`).join('');

    ['secret-ns-filter', 'policy-ns-filter', 'new-secret-ns', 'audit-ns'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            const val = el.value;
            el.innerHTML = opts;
            if (val) el.value = val;
        }
    });
}

function renderSecrets() {
    const tbody = document.getElementById('secrets-list');
    if (!state.secrets.length) {
        tbody.innerHTML = '<tr><td colspan="2" style="text-align:center; color: #94a3b8;">暂无密钥</td></tr>';
        return;
    }
    tbody.innerHTML = state.secrets.map(name => `
        <tr>
            <td>${name}</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="viewSecretDetail('${state.selectedNamespace}', '${name}')">查看</button>
            </td>
        </tr>
    `).join('');
}

function renderPolicies() {
    const tbody = document.getElementById('policies-list');
    if (!tbody) return;
    const nsFilter = document.getElementById('policy-ns-filter');
    const ns = nsFilter ? nsFilter.value : '';
    const filtered = filterPoliciesForView(ns);
    if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="11" style="text-align:center; color: #94a3b8;">暂无策略</td></tr>';
        return;
    }
    tbody.innerHTML = filtered.map(p => {
        const reqApprovals = p.required_approvals || 1;
        const approvedSteps = p.approved_steps || 0;
        const approvers = (p.approvers || []).join(', ') || '-';
        const approvedBy = (p.approved_by || []).join(', ') || '-';
        const ticket = p.ticket_id || '-';
        const effect = p.effect || 'allow';
        const subjects = formatList(p.subjects);
        const resources = formatList(p.resources);
        const actions = formatList(p.actions);
        const statusBadge = `<span class="status-badge status-${p.approval_state}">${p.approval_state}</span>`;
        const detailBtn = `<button class="btn btn-secondary btn-sm" onclick="viewPolicyDetail('${p.namespace}','${p.name}')">详情</button>`;
        let actionBtns = '-';
        if (p.approval_state === 'pending') {
            actionBtns = `
                <button class="btn btn-primary btn-sm" onclick="handlePolicyDecision('${p.namespace}','${p.name}','approve')">通过</button>
                <button class="btn btn-secondary btn-sm" onclick="handlePolicyDecision('${p.namespace}','${p.name}','reject')">拒绝</button>
            `;
        }
        return `
        <tr>
            <td>${p.name}</td>
            <td>${p.namespace || '-'}</td>
            <td>${subjects}</td>
            <td>${resources}</td>
            <td>${actions}</td>
            <td>${effect}</td>
            <td>${statusBadge}</td>
            <td>${approvedSteps}/${reqApprovals}<br/><small>approvers:${approvers}<br/>approved_by:${approvedBy}</small></td>
            <td>${p.version || 1}</td>
            <td>${ticket}</td>
            <td>${detailBtn}${p.approval_state === 'pending' ? '<br/>' + actionBtns : ''}</td>
        </tr>`;
    }).join('');
}

function renderAudits() {
    const tbody = document.getElementById('audits-list');
    tbody.innerHTML = state.audits.map(a => `
        <tr>
            <td>${new Date(a.created_at).toLocaleString('zh-CN')}</td>
            <td>${a.actor}</td>
            <td>${a.action}</td>
            <td>${a.namespace}</td>
            <td>${a.name}</td>
            <td>${a.result}</td>
        </tr>
    `).join('');
}

// Actions
window.viewNamespaceSecrets = (ns) => {
    state.selectedNamespace = ns;
    document.getElementById('secret-ns-filter').value = ns;
    window.location.hash = 'secrets';
};

window.viewSecretDetail = async (ns, name) => {
    try {
        const res = await request(`/v1/namespaces/${ns}/secrets/${name}:get`, 'POST', { version: 0 });
        document.getElementById('detail-name').textContent = name;
        document.getElementById('detail-content').textContent = JSON.stringify(res, null, 2);
        document.getElementById('secret-detail').style.display = 'block';
    } catch (e) {
        alert("加载密钥失败: " + e.message);
    }
};

window.closeDetail = () => {
    document.getElementById('secret-detail').style.display = 'none';
};

window.approvePolicy = async (ns, name) => {
    handlePolicyDecision(ns, name, 'approve');
};

function formatList(list) {
    if (!Array.isArray(list) || list.length === 0) return '-';
    return list.join(', ');
}

function filterPoliciesForView(ns) {
    const status = state.policyFilters.status || '';
    const search = (state.policyFilters.search || '').toLowerCase();
    return state.policies.filter(p => {
        if (ns && p.namespace !== ns) return false;
        if (status && p.approval_state !== status) return false;
        if (search) {
            const haystack = [
                p.name,
                (p.subjects || []).join(' '),
                (p.resources || []).join(' '),
                (p.actions || []).join(' ')
            ].join(' ').toLowerCase();
            if (!haystack.includes(search)) return false;
        }
        return true;
    });
}

function findPolicy(ns, name) {
    return state.policies.find(p => p.namespace === ns && p.name === name);
}

window.viewPolicyDetail = (ns, name) => {
    const p = findPolicy(ns, name);
    if (!p) return;
    const body = `
        <div class="form-group"><strong>名称：</strong>${p.name}</div>
        <div class="form-group"><strong>命名空间：</strong>${p.namespace || '-'}</div>
        <div class="form-group"><strong>Effect：</strong>${p.effect || 'allow'}</div>
        <div class="form-group"><strong>Subjects：</strong>${formatList(p.subjects)}</div>
        <div class="form-group"><strong>Resources：</strong>${formatList(p.resources)}</div>
        <div class="form-group"><strong>Actions：</strong>${formatList(p.actions)}</div>
        <div class="form-group"><strong>Conditions：</strong><pre style="white-space:pre-wrap;">${JSON.stringify(p.conditions || {}, null, 2)}</pre></div>
        <div class="form-group"><strong>审批进度：</strong>${p.approved_steps || 0}/${p.required_approvals || 1}</div>
        <div class="form-group"><strong>Approvers：</strong>${formatList(p.approvers)}</div>
        <div class="form-group"><strong>Approved By：</strong>${formatList(p.approved_by)}</div>
        <div class="form-group"><strong>Quota：</strong>${p.quota || '-'}</div>
        <div class="form-group"><strong>Version：</strong>${p.version || 1}</div>
        <div class="form-group"><strong>Ticket：</strong>${p.ticket_id || '-'}</div>
        <div class="form-group"><strong>创建人/时间：</strong>${p.created_by || '-'} / ${p.created_at || '-'}</div>
        <div class="form-group"><strong>审批时间：</strong>${p.approved_at || '-'}</div>
        <pre>${JSON.stringify(p, null, 2)}</pre>
    `;
    showModal('策略详情', body, async () => { }, '关闭');
    // Hide cancel button for detail view
    document.querySelector('#modal-confirm-btn').previousElementSibling.style.display = 'none';
};

window.handlePolicyDecision = (ns, name, decision) => {
    const p = findPolicy(ns, name);
    if (!p) return;
    const title = decision === 'approve' ? '审批通过策略' : '拒绝策略';
    const body = `
        <p>策略：${p.name}（ns: ${p.namespace || '-'}）</p>
        <p>当前版本：${p.version || 1}，状态：${p.approval_state}</p>
        <div class="form-group">
            <label>审批意见（可选）</label>
            <textarea id="policy-reason" rows="3" placeholder="审批理由"></textarea>
        </div>
        <div class="form-group">
            <label>工单号（可选）</label>
            <input id="policy-ticket" type="text" placeholder="ticket id">
        </div>
    `;
    showModal(title, body, async () => {
        const reason = document.getElementById('policy-reason').value;
        const ticket = document.getElementById('policy-ticket').value;
        await request('/proxy/approve', 'POST', {
            action: 'approve',
            namespace: ns,
            name: name,
            decision: decision,
            reason: reason,
            ticket_id: ticket,
            version: p.version
        });
        alert(decision === 'approve' ? '审批成功' : '已拒绝');
        await loadPolicies(ns, true);
    }, decision === 'approve' ? '通过' : '拒绝');
};

// Modals
function showModal(title, bodyHtml, onConfirm, confirmText = '确认') {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = bodyHtml;
    const overlay = document.getElementById('modal-overlay');
    overlay.classList.add('active');
    const confirmBtn = document.getElementById('modal-confirm-btn');
    confirmBtn.textContent = confirmText || '确认';

    confirmBtn.onclick = async () => {
        await onConfirm();
        closeModal();
    };
}

window.closeModal = () => {
    document.getElementById('modal-overlay').classList.remove('active');
    const confirmBtn = document.getElementById('modal-confirm-btn');
    if (confirmBtn && confirmBtn.previousElementSibling) {
        confirmBtn.previousElementSibling.style.display = '';
    }
};

window.showCreateNamespaceModal = () => {
    showModal('创建命名空间', `
        <div class="form-group">
            <label>名称</label>
            <input id="new-ns-name" type="text" placeholder="prod">
        </div>
        <div class="form-group">
            <label>描述</label>
            <input id="new-ns-desc" type="text" placeholder="生产环境">
        </div>
    `, async () => {
        const name = document.getElementById('new-ns-name').value;
        const desc = document.getElementById('new-ns-desc').value;
        await request('/v1/admin/namespaces', 'POST', { name, description: desc, ticket_id: 'manual' });
        loadNamespaces();
    });
};

window.showCreateSecretModal = () => {
    const nsOptions = state.namespaces.map(ns => `<option value="${ns}">${ns}</option>`).join('');
    showModal('创建密钥', `
        <div class="form-group">
            <label>命名空间</label>
            <select id="new-secret-ns">${nsOptions}</select>
        </div>
        <div class="form-group">
            <label>名称</label>
            <input id="new-secret-name" type="text">
        </div>
        <div class="form-group">
            <label>Key ID</label>
            <input id="new-secret-keyid" type="text" placeholder="k1">
        </div>
        <div class="form-group">
            <label>过期时间 (可选)</label>
            <input id="new-secret-expire" type="datetime-local">
        </div>
        <div class="form-group">
            <label>值 (明文)</label>
            <textarea id="new-secret-val" rows="3"></textarea>
            <button id="generate-secret-btn" class="btn btn-primary" style="width: 100%; margin-top: 8px; justify-content: center;">生成</button>
        </div>
    `, async () => {
        const ns = document.getElementById('new-secret-ns').value;
        const name = document.getElementById('new-secret-name').value;
        const keyID = document.getElementById('new-secret-keyid').value;
        const val = document.getElementById('new-secret-val').value;
        const expire = document.getElementById('new-secret-expire').value;

        if (!name || !keyID) {
            alert('名称与 Key ID 必填');
            return;
        }

        const body = {
            name,
            key_id: keyID,
            plaintext: val,
            labels: { created_via: 'portal' }
        };

        if (expire) {
            body.expire_at = new Date(expire).toISOString();
        }

        await request(`/v1/namespaces/${ns}/secrets`, 'POST', body);
        if (state.selectedNamespace === ns) loadSecrets(ns);
    });

    document.getElementById('generate-secret-btn').onclick = (e) => {
        e.preventDefault(); // Prevent any default form submission if applicable
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+';
        let result = '';
        for (let i = 0; i < 64; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        document.getElementById('new-secret-val').value = result;
    };
};

window.showCreatePolicyModal = () => {
    const nsOptions = state.namespaces.map(ns => `<option value="${ns}">${ns}</option>`).join('');
    showModal('创建策略', `
        <div class="form-group">
            <label>名称 *</label>
            <input id="new-policy-name" type="text" placeholder="policy-name">
        </div>
        <div class="form-group">
            <label>命名空间 *</label>
            <select id="new-policy-ns">${nsOptions}</select>
        </div>
        <div class="form-group">
            <label>主体 (Subjects) * <small>逗号分隔</small></label>
            <input id="new-policy-subjects" type="text" placeholder="admin, user-1">
        </div>
        <div class="form-group">
            <label>资源 (Resources) * <small>逗号分隔</small></label>
            <input id="new-policy-resources" type="text" placeholder="*, secrets/*">
        </div>
        <div class="form-group">
            <label>动作 (Actions) * <small>逗号分隔</small></label>
            <input id="new-policy-actions" type="text" placeholder="read, write">
        </div>
        <div class="form-group">
            <label>Effect</label>
            <select id="new-policy-effect">
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
            </select>
        </div>
        <div class="form-group">
            <label>所需审批人数</label>
            <input id="new-policy-approvals" type="number" value="1" min="1">
        </div>
        <div class="form-group">
            <label>指定审批人 (Approvers) <small>逗号分隔，可选</small></label>
            <input id="new-policy-approvers" type="text" placeholder="admin">
        </div>
        <div class="form-group">
            <label>工单号 (Ticket ID) <small>可选</small></label>
            <input id="new-policy-ticket" type="text">
        </div>
    `, async () => {
        const name = document.getElementById('new-policy-name').value;
        const ns = document.getElementById('new-policy-ns').value;
        const subjects = document.getElementById('new-policy-subjects').value;
        const resources = document.getElementById('new-policy-resources').value;
        const actions = document.getElementById('new-policy-actions').value;
        const effect = document.getElementById('new-policy-effect').value;
        const approvals = parseInt(document.getElementById('new-policy-approvals').value) || 1;
        const approvers = document.getElementById('new-policy-approvers').value;
        const ticket = document.getElementById('new-policy-ticket').value;

        if (!name || !ns || !subjects || !resources || !actions) {
            alert('请填写所有必填项 (*)');
            throw new Error("Missing required fields");
        }

        const split = (str) => str.split(',').map(s => s.trim()).filter(s => s);

        await request('/v1/authz/policies', 'POST', {
            action: 'create',
            name: name,
            namespace: ns,
            subjects: split(subjects),
            resources: split(resources),
            actions: split(actions),
            effect: effect,
            required_approvals: approvals,
            approvers: split(approvers),
            ticket_id: ticket
        });
        alert('策略创建请求已提交');
        loadPolicies(ns, true);
    });
};
