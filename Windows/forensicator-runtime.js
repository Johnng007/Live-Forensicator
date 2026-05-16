
/* ═══════════════════════════════════════════════════════════════════════════
   ENGINE — all rendering logic below
═══════════════════════════════════════════════════════════════════════════ */

// severity config
var SEV = {
  critical:      { label:'CRITICAL', bg:'#ef4444', fg:'#fff' },
  high:          { label:'HIGH',     bg:'#f97316', fg:'#fff' },
  medium:        { label:'MEDIUM',   bg:'#eab308', fg:'#111' },
  low:           { label:'LOW',      bg:'#22c55e', fg:'#111' },
  informational: { label:'INFO',     bg:'#3b82f6', fg:'#fff' }
};

function sevCfg(lv) {
  return SEV[(lv||'').toLowerCase()] || { label:(lv||'INFO').toUpperCase(), bg:'#555', fg:'#fff' };
}

function esc(s) {
  return String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function sevBadge(lv) {
  var c = sevCfg(lv);
  return '<span class="sev" style="background:'+c.bg+';color:'+c.fg+'">'+esc(c.label)+'</span>';
}

/* ── NAV ────────────────────────────────────────────────────────────────────── */
function nav(id) {
  document.querySelectorAll('.view').forEach(function(v){ v.classList.remove('active'); });
  document.querySelectorAll('.sb-link').forEach(function(l){ l.classList.remove('active'); });
  var v = document.getElementById('view-'+id);
  if (v) v.classList.add('active');
  document.querySelectorAll('.sb-link').forEach(function(l){
    if (l.getAttribute('onclick') && l.getAttribute('onclick').includes("'"+id+"'")) l.classList.add('active');
  });
  window.scrollTo(0,0);
}

/* ── TABLE FILTER ───────────────────────────────────────────────────────────── */
/* ══════════════════════════════════════════════════════════════════════════════
   PAGINATION ENGINE
   Usage:  initPagination(tbodyId, filterColIndexes, pageSize)
   All existing  oninput="filterTable('xxx-tbody', ...)"  calls work unchanged —
   filterTable checks the registry and delegates automatically.
══════════════════════════════════════════════════════════════════════════════ */
var _paginators = {};

function PaginatedTable(tbodyId, filterCols, pageSize) {
  this.id        = tbodyId;
  this.cols      = filterCols || [];
  this.pageSize  = pageSize   || 25;
  this.page      = 1;
  this.query     = '';
  this.allRows   = [];
  this.filtered  = [];
  this.footerId  = tbodyId + '-pgbar';

  this._readRows();
  this._ensureBar();
  this.render();
}

PaginatedTable.prototype._readRows = function () {
  var tbody = document.getElementById(this.id);
  this.allRows = [];
  if (!tbody) return;

  var rows = Array.from(tbody.children).filter(function (node) {
    return node.tagName && node.tagName.toLowerCase() === 'tr';
  });
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.classList.contains('d-detail')) continue;
    if (isPlaceholderRow(row)) continue;

    var item = { row: row, detail: null };
    if (row.classList.contains('d-row') && rows[i + 1] && rows[i + 1].classList.contains('d-detail')) {
      item.detail = rows[i + 1];
      i++;
    }
    this.allRows.push(item);
  }
};

PaginatedTable.prototype._ensureBar = function () {
  if (document.getElementById(this.footerId)) return;
  var tbody = document.getElementById(this.id);
  if (!tbody) return;
  var wrap  = tbody.closest('.tbl-wrap') || tbody.closest('.disc-wrap');
  var panel = tbody.closest('.panel');
  var bar   = document.createElement('div');
  bar.id        = this.footerId;
  bar.className = 'pg-bar';
  if (wrap) {
    /* insert bar after the wrap div, stays inside the panel */
    wrap.parentNode.insertBefore(bar, wrap.nextSibling);
  } else if (panel) {
    /* no tbl-wrap / disc-wrap — append to panel */
    panel.appendChild(bar);
  }
  /* else: no suitable container — skip gracefully (no crash) */
};

PaginatedTable.prototype.filter = function (q) {
  this.query = q;
  this.page  = 1;
  this.render();
};

PaginatedTable.prototype.goPage = function (p) {
  this.page = p;
  this.render();
  var tbody = document.getElementById(this.id);
  if (tbody) {
    var panel = tbody.closest('.panel');
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
};

PaginatedTable.prototype.setPageSize = function (n) {
  this.pageSize = n;
  this.page     = 1;
  this.render();
};

PaginatedTable.prototype.reload = function () {
  this._readRows();
  this.page = 1;
  this.render();
};

PaginatedTable.prototype.render = function () {
  var q    = this.query.toLowerCase();
  var cols = this.cols;

  this.filtered = this.allRows.filter(function (item) {
    if (!q) return true;
    var tds = item.row.querySelectorAll('td');
    return cols.map(function (i) {
      return tds[i] ? tds[i].innerText : '';
    }).join(' ').toLowerCase().indexOf(q) !== -1;
  });

  var total = this.filtered.length;
  var pages = Math.max(1, Math.ceil(total / this.pageSize));
  if (this.page > pages) this.page = pages;

  var start = (this.page - 1) * this.pageSize;
  var end   = start + this.pageSize;

  this.allRows.forEach(function (item) {
    item.row.style.display = 'none';
    if (item.detail) item.detail.style.display = 'none';
  });
  this.filtered.forEach(function (item, i) {
    var isVisible = i >= start && i < end;
    item.row.style.display = isVisible ? '' : 'none';
    if (item.detail) {
      item.detail.style.display = isVisible && item.detail.dataset.expanded === 'true' ? 'table-row' : 'none';
    }
  });

  this._renderBar(total, pages, start, end);
  syncLiveBadge(this.id, total);
};

PaginatedTable.prototype._renderBar = function (total, pages, start, end) {
  var bar = document.getElementById(this.footerId);
  if (!bar) return;
  if (total === 0) { bar.innerHTML = ''; return; }

  var self = this;
  var html = '<div class="pg-info">Showing '
    + (start + 1) + '–' + Math.min(end, total)
    + ' of ' + total + ' rows</div>';

  html += '<div class="pg-controls">';
  html += '<select class="pg-select" onchange="_paginators[\'' + this.id + '\'].setPageSize(+this.value);this.blur()">';
  [25, 50, 100, 250].forEach(function (n) {
    html += '<option value="' + n + '"' + (n === self.pageSize ? ' selected' : '') + '>' + n + ' / page</option>';
  });
  html += '</select>';

  html += '<button class="pg-btn" ' + (this.page <= 1 ? 'disabled' : '')
        + ' onclick="_paginators[\'' + this.id + '\'].goPage(' + (this.page - 1) + ')">‹</button>';

  this._pageRange(pages).forEach(function (p) {
    if (p === '…') {
      html += '<span class="pg-ellipsis">…</span>';
    } else {
      html += '<button class="pg-btn' + (p === self.page ? ' pg-active' : '') + '"'
            + ' onclick="_paginators[\'' + self.id + '\'].goPage(' + p + ')">' + p + '</button>';
    }
  });

  html += '<button class="pg-btn" ' + (this.page >= pages ? 'disabled' : '')
        + ' onclick="_paginators[\'' + this.id + '\'].goPage(' + (this.page + 1) + ')">›</button>';

  html += '</div>';
  bar.innerHTML = html;
};

PaginatedTable.prototype._pageRange = function (pages) {
  if (pages <= 7) {
    var r = [];
    for (var i = 1; i <= pages; i++) r.push(i);
    return r;
  }
  var p   = this.page;
  var out = [1];
  if (p > 3)          out.push('…');
  for (var i = Math.max(2, p - 1); i <= Math.min(pages - 1, p + 1); i++) out.push(i);
  if (p < pages - 2)  out.push('…');
  out.push(pages);
  return out;
};

function initPagination(tbodyId, filterCols, pageSize) {
  try {
    _paginators[tbodyId] = new PaginatedTable(tbodyId, filterCols, pageSize || 25);
  } catch(e) { console.error('[Forensicator] initPagination failed:', tbodyId, e); }
}

/* ── TABLE FILTER — routes through paginator if registered ───────────────── */
function filterTable(tbodyId, q, cols) {
  if (_paginators[tbodyId]) {
    _paginators[tbodyId].filter(q);
    return;
  }
  var tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  var count = 0;
  tbody.querySelectorAll('tr').forEach(function (r) {
    var tds  = r.querySelectorAll('td');
    var text = cols.map(function (i) { return tds[i] ? tds[i].innerText : ''; })
                   .join(' ').toLowerCase();
    var show = !q || text.indexOf(q.toLowerCase()) !== -1;
    r.style.display = show ? '' : 'none';
    if (show) count++;
  });
  syncLiveBadge(tbodyId, count);
  return count;
}

function getLinkedCountId(tbodyId) {
  if (!tbodyId || tbodyId.slice(-6) !== '-tbody') return null;
  return tbodyId.slice(0, -6) + '-count';
}

function setCountBadge(countId, countValue) {
  var badge = document.getElementById(countId);
  if (badge) badge.textContent = countValue;
}

function isPlaceholderRow(row) {
  if (!row) return true;
  if (row.classList.contains('d-detail')) return true;
  var cells = row.querySelectorAll('td');
  if (!cells.length) return true;
  if (cells.length === 1 && cells[0].hasAttribute('colspan')) return true;
  var txt = (row.textContent || '').trim().toLowerCase();
  return !txt || txt === 'no data' || txt === 'no data available' || txt.indexOf('no matches found') !== -1 || txt.indexOf('hash lookup skipped') !== -1 || txt.indexOf('not collected') === 0;
}

function refreshPagination(tbodyId) {
  if (_paginators[tbodyId]) {
    _paginators[tbodyId].reload();
    return;
  }
  var countId = getLinkedCountId(tbodyId);
  if (countId) syncCount(tbodyId, countId);
}

function syncLiveBadge(tbodyId, countValue) {
  var countId = getLinkedCountId(tbodyId);
  if (countId) setCountBadge(countId, countValue);
  if (tbodyId === 'net-tbody' || tbodyId === 'listen-tbody') {
    syncNetworkCards(true);
  }
}

function getDataRows(tbody) {
  if (!tbody) return [];
  return Array.from(tbody.querySelectorAll('tr')).filter(function (row) {
    return !isPlaceholderRow(row) && !row.classList.contains('d-detail');
  });
}

function getVisibleDataRows(tbody) {
  return getDataRows(tbody).filter(function (row) {
    return row.style.display !== 'none';
  });
}


/* ── AUTO-COUNT ── reads any tbody and updates its panel-count badge ── */
function syncCount(tbodyId, countId) {
  var tbody = document.getElementById(tbodyId);
  var badge = document.getElementById(countId);
  if (!tbody || !badge) return;
  badge.textContent = getDataRows(tbody).length;
}

function isExternalIp(ip) {
  var value = String(ip || '').trim().toLowerCase();
  if (!value || value === '*' || value === '::' || value === '0.0.0.0') return false;
  if (value === '::1' || value.indexOf('127.') === 0) return false;
  if (value.indexOf('10.') === 0 || value.indexOf('192.168.') === 0 || value.indexOf('169.254.') === 0) return false;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(value)) return false;
  if (value.indexOf('fe80:') === 0 || value.indexOf('fc') === 0 || value.indexOf('fd') === 0) return false;
  if (value === 'localhost') return false;
  return true;
}

function syncNetworkCards(visibleOnly) {
  var picker = visibleOnly ? getVisibleDataRows : getDataRows;
  var netRows = picker(document.getElementById('net-tbody'));
  var listenRows = picker(document.getElementById('listen-tbody'));

  var established = netRows.filter(function (row) {
    var cells = row.querySelectorAll('td');
    return cells[4] && String(cells[4].textContent || '').trim().toLowerCase() === 'established';
  }).length;

  var external = netRows.filter(function (row) {
    var cells = row.querySelectorAll('td');
    return cells[2] && isExternalIp(cells[2].textContent);
  }).length;

  var establishedEl = document.getElementById('net-established-count');
  var listenEl = document.getElementById('net-listen-count');
  var externalEl = document.getElementById('net-external-count');

  if (establishedEl) establishedEl.textContent = established;
  if (listenEl) listenEl.textContent = listenRows.length;
  if (externalEl) externalEl.textContent = external;
}

function normalizeEventLogPanels() {
  var panels = Array.from(document.querySelectorAll('#view-eventlog .panel')).filter(function (panel) {
    return !!panel.querySelector('tbody[id="evtlog-tbody"]');
  });

  panels.forEach(function (panel, idx) {
    var prefix = 'evtlog-' + (idx + 1);
    var tbody = panel.querySelector('tbody[id="evtlog-tbody"]');
    var count = panel.querySelector('span[id="evtlog-count"]');
    var search = panel.querySelector('input[id="evtlog-search"]');
    var hits = panel.querySelector('div[id="evtlog-hits"]');
    var filters = panel.querySelector('div[id="evtlog-filters"]');

    if (!tbody) return;

    tbody.id = prefix + '-tbody';

    if (count) count.id = prefix + '-count';
    if (hits) hits.id = prefix + '-hits';
    if (filters) {
      filters.id = prefix + '-filters';
      filters.innerHTML = '';
    }

    if (search) {
      search.id = prefix + '-search';
      search.setAttribute('oninput', "filterTable('" + tbody.id + "', this.value, [0,1,2,3,4,5,6,7,8])");
    }

    initPagination(tbody.id, [0,1,2,3,4,5,6,7,8], 25);
    if (count) syncCount(tbody.id, count.id);
  });
}


/* ── DETECT RENDER ──────────────────────────────────────────────────────────── */
var detActive = 'all';

function buildDetFilters(data) {
  var cnt = { all: data.length, critical:0, high:0, medium:0, low:0, informational:0 };
  data.forEach(function(d){ var lv=(d.RuleLevel||'informational').toLowerCase(); if(cnt[lv]!==undefined) cnt[lv]++; });
  var pills = [
    ['all','All',cnt.all,'#3b82f6','rgba(59,130,246,.15)'],
    ['critical','Critical',cnt.critical,'#ef4444','rgba(239,68,68,.15)'],
    ['high','High',cnt.high,'#f97316','rgba(249,115,22,.15)'],
    ['medium','Medium',cnt.medium,'#eab308','rgba(234,179,8,.15)'],
    ['low','Low',cnt.low,'#22c55e','rgba(34,197,94,.15)'],
    ['informational','Info',cnt.informational,'#3b82f6','rgba(59,130,246,.15)']
  ];
  return pills.map(function(p){
    var isA = detActive===p[0];
    return '<div class="f-pill" style="border-color:'+p[3]+';background:'+(isA?p[4]:'transparent')+';color:'+p[3]+'" onclick="setDetLevel(\''+p[0]+'\')">'
      +'<span class="f-num">'+p[2]+'</span> '+p[1]+'</div>';
  }).join('');
}

function setDetLevel(lv) {
  detActive = lv;
  renderDetections();
}

function renderDiscoverTable(data, tbodyId, searchId, hitsId, filterRowId, allData) {
  var q = searchId ? (document.getElementById(searchId)||{value:''}).value.toLowerCase() : '';
  var filtered = (allData||data).filter(function(d){
    if (detActive!=='all' && (d.RuleLevel||'informational').toLowerCase()!==detActive) return false;
    if (!q) return true;
    return [d.RuleTitle,d.User,d.Process,d.CommandLine,d.RuleTags,String(d.EventId||'')]
      .join(' ').toLowerCase().indexOf(q)!==-1;
  });

  if (filterRowId) {
    var fr = document.getElementById(filterRowId);
    if (fr) fr.innerHTML = buildDetFilters(allData||data);
  }

  if (hitsId) {
    var h = document.getElementById(hitsId);
    if (h) h.textContent = filtered.length+' hit'+(filtered.length!==1?'s':'');
  }

  var tbody = document.getElementById(tbodyId);
  if (!tbody) return;

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-icon">'
      +((allData||data).length===0?'✔':'🔍')+'</div><div class="empty-msg">'
      +((allData||data).length===0?'No findings on this host.':'No results match the current filter.')
      +'</div></div></td></tr>';
    return;
  }

  var rows = [];
  filtered.forEach(function(d,i){
    var uid = tbodyId+'-'+i;
    var c = sevCfg(d.RuleLevel);
    var procFull = String(d.Process||'N/A');
    var procSh = procFull.length>52 ? '&hellip;'+esc(procFull.slice(-52)) : esc(procFull);
    rows.push(
      '<tr class="d-row" style="border-left:3px solid '+c.bg+'" onclick="toggleDRow(\''+uid+'\')">'
      +'<td class="d-expand" id="ico-'+uid+'">▶</td>'
      +'<td class="d-time">'+esc(d.TimeCreated)+'</td>'
      +'<td>'+sevBadge(d.RuleLevel)+'</td>'
      +'<td class="d-rule"><strong>'+esc(d.RuleTitle)+'</strong></td>'
      +'<td class="d-evid">'+esc(String(d.EventId||''))+'</td>'
      +'<td class="d-user">'+esc(d.User||'N/A')+'</td>'
      +'<td class="d-proc" title="'+esc(procFull)+'">'+procSh+'</td>'
      +'</tr>'
    );
    rows.push(
      '<tr id="det-'+uid+'" class="d-detail" style="display:none">'
      +'<td colspan="7"><div class="kv-panel"><table>'
      +kv('rule.title',d.RuleTitle)+kv('rule.level',d.RuleLevel)
      +kv('rule.tags',d.RuleTags)+kv('rule.file',d.RuleFile)
      +kv('event.id',d.EventId)+kv('event.log_name',d.LogName)
      +kv('@timestamp',d.TimeCreated)+kv('user.name',d.User)
      +kv('process.executable',d.Process)+kvCode('process.command_line',d.CommandLine)
      +'</table></div></td></tr>'
    );
  });
  tbody.innerHTML = rows.join('');
}

function kv(k,v){ return '<tr><td class="kv-k">'+esc(k)+'</td><td class="kv-v">'+esc(String(v==null?'N/A':v))+'</td></tr>'; }
function kvCode(k,v){ return '<tr><td class="kv-k">'+esc(k)+'</td><td class="kv-v"><code>'+esc(String(v==null?'N/A':v))+'</code></td></tr>'; }

window.toggleDRow = function(uid) {
  var det = document.getElementById('det-'+uid);
  var ico = document.getElementById('ico-'+uid);
  if (!det) return;
  var open = det.style.display==='none'||!det.style.display;
  det.dataset.expanded = open ? 'true' : 'false';
  det.style.display = open ? 'table-row' : 'none';
  ico.innerHTML = open ? '▼' : '▶';
};

function renderDetections() {
  renderDiscoverTable(SIGMA_DATA, 'det-tbody', 'det-search', 'det-hits', 'det-filter-row', SIGMA_DATA);
  refreshPagination('det-tbody');
}

/* ── EVENT LOG RENDER ───────────────────────────────────────────────────────── */
var evtLogActive = 'all';

function renderEventLog(q) {
  var source = (typeof SAMPLE_EVTLOG_DATA !== 'undefined' && Array.isArray(SAMPLE_EVTLOG_DATA)) ? SAMPLE_EVTLOG_DATA : null;
  if (!source) {
    var existingRows = document.querySelectorAll('#evtlog-tbody tr.d-row').length;
    var hitsEl = document.getElementById('evtlog-hits');
    var countEl = document.getElementById('evtlog-count');
    if (hitsEl) hitsEl.textContent = existingRows + ' events';
    if (countEl) countEl.textContent = existingRows;
    return;
  }

  var filtered = source.filter(function(e){
    if (evtLogActive!=='all' && e.Category!==evtLogActive) return false;
    if (!q) return true;
    return [String(e.EventId),e.User,e.Category,e.Message].join(' ').toLowerCase().indexOf(q.toLowerCase())!==-1;
  });

  document.getElementById('evtlog-hits').textContent = filtered.length+' events';
  document.getElementById('evtlog-count').textContent = filtered.length;

  // Build category filter
  var cats = {};
  source.forEach(function(e){ cats[e.Category]=(cats[e.Category]||0)+1; });
  var catColors = { 'Logon':'#3b82f6','Process Creation':'#f97316','Account Management':'#ef4444','Scheduled Task':'#eab308','Object Access':'#a855f7' };
  var pills = '<div class="f-pill '+(evtLogActive==='all'?'active':'')+'" style="border-color:#3b82f6;color:#3b82f6" onclick="setEvtCat(\'all\')"><span class="f-num">'+source.length+'</span> All</div>';
  Object.keys(cats).forEach(function(c){
    var col = catColors[c]||'#94a3b8';
    pills += '<div class="f-pill '+(evtLogActive===c?'active':'')+'" style="border-color:'+col+';color:'+col+'" onclick="setEvtCat(\''+c+'\')">'
      +'<span class="f-num">'+cats[c]+'</span> '+c+'</div>';
  });
  document.getElementById('evtlog-filters').innerHTML = pills;

  var rows = [];
  filtered.forEach(function(e,i){
    var uid = 'evtlog-'+i;
    rows.push(
      '<tr class="d-row" onclick="toggleDRow(\''+uid+'\')">'
      +'<td class="d-expand" id="ico-'+uid+'">▶</td>'
      +'<td class="d-time">'+esc(e.Time)+'</td>'
      +'<td class="d-evid">'+esc(String(e.EventId))+'</td>'
      +'<td><span style="font-size:11px;color:#94a3b8">'+esc(e.Category)+'</span></td>'
      +'<td class="d-user">'+esc(e.User)+'</td>'
      +'<td class="d-proc">'+esc(e.Computer)+'</td>'
      +'<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#94a3b8">'+esc(e.Message)+'</td>'
      +'</tr>'
    );
    rows.push(
      '<tr id="det-'+uid+'" class="d-detail" style="display:none">'
      +'<td colspan="7"><div class="kv-panel"><table>'
      +kv('event.id',e.EventId)+kv('event.category',e.Category)
      +kv('@timestamp',e.Time)+kv('user.name',e.User)
      +kv('host.name',e.Computer)+kvCode('message',e.Message)
      +'</table></div></td></tr>'
    );
  });
  document.getElementById('evtlog-tbody').innerHTML = rows.join('');
  refreshPagination('evtlog-tbody');

  // Category bars
  buildBars('evtlog-category-bars', cats, catColors);
  // Event ID bars
  var evids = {};
  source.forEach(function(e){ var k='EID '+e.EventId; evids[k]=(evids[k]||0)+1; });
  buildBars('evtlog-evid-bars', evids, {});
}

window.setEvtCat = function(c){ evtLogActive=c; renderEventLog(''); };

/* ── BAR CHART BUILDER ──────────────────────────────────────────────────────── */
function buildBars(containerId, data, colors) {
  var el = document.getElementById(containerId);
  if (!el) return;
  var entries = Object.entries(data).sort(function(a,b){ return b[1]-a[1]; }).slice(0,8);
  var max = entries.reduce(function(m,e){ return Math.max(m,e[1]); }, 1);
  var defaultColors = ['#3b82f6','#f97316','#ef4444','#eab308','#22c55e','#a855f7','#ec4899','#14b8a6'];
  el.innerHTML = entries.map(function(e,i){
    var pct = Math.round(e[1]/max*100);
    var col = colors[e[0]] || defaultColors[i%defaultColors.length];
    return '<div class="bar-row">'
      +'<div class="bar-label" title="'+esc(e[0])+'">'+esc(e[0])+'</div>'
      +'<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:'+col+'"></div></div>'
      +'<div class="bar-val">'+e[1]+'</div>'
      +'</div>';
  }).join('');
}

/* ── BROWSER FILTER ─────────────────────────────────────────────────────────── */
window.filterBrowser = function(mode) {
  var tbody = document.getElementById('browser-tbody');
  var rows = document.querySelectorAll('#browser-tbody tr');
  rows.forEach(function(r){
    if (mode==='ioc') {
      r.style.display = r.querySelector('.flag-cell') ? '' : 'none';
    } else {
      r.style.display = '';
    }
  });
  syncLiveBadge('browser-tbody', getVisibleDataRows(tbody).length);
};

/* ── OVERVIEW BUILD ─────────────────────────────────────────────────────────── */
function buildOverview() {
  var totalDet = SIGMA_DATA.length + HASH_DATA.length + IOC_DATA.length;
  var crits = SIGMA_DATA.filter(function(d){ return (d.RuleLevel||'').toLowerCase()==='critical'; }).length
            + HASH_DATA.filter(function(d){ return (d.RuleLevel||'').toLowerCase()==='critical'; }).length;

  // Stat row
  var stats = [
    { n: totalDet,          lbl:'Total Detections', accent:'var(--crit)',  view:'detections' },
    { n: crits,             lbl:'Critical',         accent:'var(--crit)',  view:'detections' },
    { n: SIGMA_DATA.length, lbl:'Sigma Hits',       accent:'var(--high)',  view:'detections' },
    { n: HASH_DATA.length,  lbl:'Hash Matches',     accent:'var(--med)',   view:'hashes'     },
    { n: IOC_DATA.length,   lbl:'IOC Matches',      accent:'var(--blue)',  view:'ioc'        }
  ];
  document.getElementById('overview-stats').innerHTML = stats.map(function(s){
    return '<div class="stat-card" style="--accent:'+s.accent+'" onclick="nav(\''+s.view+'\')">'
      +'<div class="stat-num">'+s.n+'</div>'
      +'<div class="stat-label">'+s.lbl+'</div>'
      +'</div>';
  }).join('');

  // Alert banners
  var banners = '';
  if (crits) banners += '<div class="alert-banner crit">🔴 <strong>'+crits+' CRITICAL</strong> finding'+(crits!==1?'s':'')+' detected — immediate review required.</div>';
  if (SIGMA_DATA.filter(function(d){ return (d.RuleLevel||'').toLowerCase()==='high'; }).length)
    banners += '<div class="alert-banner high">🟠 High-severity Sigma rule matches detected.</div>';
  if (!totalDet) banners = '<div class="alert-banner info">✔ No detections found on this host.</div>';
  document.getElementById('overview-alerts').innerHTML = banners;

  // Severity bars
  var sevCounts = {};
  SIGMA_DATA.concat(HASH_DATA).concat(IOC_DATA).forEach(function(d){
    var lv = (d.RuleLevel||'informational');
    lv = lv.charAt(0).toUpperCase()+lv.slice(1);
    sevCounts[lv] = (sevCounts[lv]||0)+1;
  });
  var sevColors = { Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#22c55e',Informational:'#3b82f6' };
  buildBars('sev-bars', sevCounts, sevColors);

  // Sidebar badges
  function showBadge(id, n) {
    var b = document.getElementById('badge-'+id);
    if (!b) return;
    b.textContent = n;
    b.classList.toggle('show', n > 0);
  }
  showBadge('detections', SIGMA_DATA.length);
  showBadge('hashes',     HASH_DATA.length);
  showBadge('ioc',        IOC_DATA.length);

  // Top hits table is server-rendered from PowerShell ($sigmaFindings).
}

/* ── HASH & IOC TABLES ──────────────────────────────────────────────────────── */
function renderSimpleDetectTable(data, tbodyId, countId, col4Label, col4Field) {
  var count = document.getElementById(countId);
  var tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (count) count.textContent = data.length;
  if (!data.length) {
    if (tbody.querySelectorAll('tr').length) {
      refreshPagination(tbodyId);
      return;
    }
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-icon">✔</div><div class="empty-msg">No matches found on this host.</div></div></td></tr>';
    refreshPagination(tbodyId);
    return;
  }
  var rows = [];
  data.forEach(function(d,i){
    var uid = tbodyId+'-'+i;
    var c = sevCfg(d.RuleLevel);
    rows.push(
      '<tr class="d-row" style="border-left:3px solid '+c.bg+'" onclick="toggleDRow(\''+uid+'\')">'
      +'<td class="d-expand" id="ico-'+uid+'">▶</td>'
      +'<td class="d-time">'+esc(d.TimeCreated)+'</td>'
      +'<td>'+sevBadge(d.RuleLevel)+'</td>'
      +'<td class="d-rule"><strong>'+esc(d.RuleTitle)+'</strong></td>'
      +'<td class="d-proc" style="max-width:300px">'+esc(d.Process||'')+'</td>'
      +'<td class="d-proc" style="color:#94a3b8">'+esc(d.CommandLine||'')+'</td>'
      +'<td style="font-size:11px;color:#94a3b8">'+esc(d.RuleFile||'')+'</td>'
      +'</tr>'
    );
    rows.push(
      '<tr id="det-'+uid+'" class="d-detail" style="display:none">'
      +'<td colspan="7"><div class="kv-panel"><table>'
      +kv('rule.title',d.RuleTitle)+kv('rule.level',d.RuleLevel)
      +kv('@timestamp',d.TimeCreated)+kv('user.name',d.User)
      +kv('process.executable',d.Process)+kvCode('details',d.CommandLine)
      +kv('source',d.RuleFile)
      +'</table></div></td></tr>'
    );
  });
  tbody.innerHTML = rows.join('');
  refreshPagination(tbodyId);
}

/* ── EVENT LOG BAR CHARTS ───────────────────────────────────────────────────── */
/* Known mapping: EVTLOG_COUNTS category name → Windows Event IDs */
var EVTLOG_EID_MAP = {
  'Group Enumeration':        [4798, 4799],
  'RDP Logins':               [4624, 4778],
  'RDP Auths':                [1149],
  'Outgoing RDP':             [1102],
  'Created Users':            [4720],
  'Password Resets':          [4724],
  'Added to Group':           [4732, 4728],
  'Enabled Users':            [4722],
  'Disabled Users':           [4723],
  'Deleted Users':            [4726],
  'Locked Out Users':         [4740],
  'Cred Manager Backup':      [5376],
  'Cred Manager Restore':     [5377],
  'Logon Events':             [4624],
  'Failed Logon Events':      [4625],
  'Object Access Events':     [4656, 4663],
  'Process Execution Events': [4688]
};

function buildEventLogBarCharts() {
  var defaultColors = ['#3b82f6','#f97316','#ef4444','#eab308','#22c55e','#a855f7','#ec4899','#14b8a6'];

  // ── Category bars: from EVTLOG_COUNTS ──
  var cats = {};
  if (typeof EVTLOG_COUNTS === 'object' && EVTLOG_COUNTS !== null) {
    Object.keys(EVTLOG_COUNTS).forEach(function(label) {
      var n = EVTLOG_COUNTS[label];
      if (n > 0) cats[label] = n;
    });
  }
  buildBars('evtlog-category-bars', cats, {});

  // ── Event ID bars: sum counts per event ID from the known mapping ──
  var evids = {};
  if (typeof EVTLOG_COUNTS === 'object' && EVTLOG_COUNTS !== null) {
    Object.keys(EVTLOG_COUNTS).forEach(function(label) {
      var count = EVTLOG_COUNTS[label];
      if (!count || count <= 0) return;
      var ids = EVTLOG_EID_MAP[label];
      if (!ids) return;
      var perId = Math.floor(count / ids.length);
      ids.forEach(function(eid) {
        var k = 'EID ' + eid;
        evids[k] = (evids[k] || 0) + perId;
      });
    });
  }
  buildBars('evtlog-evid-bars', evids, {});
}

/* ── BOOT ─────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  try { normalizeEventLogPanels(); } catch(e) { console.error('[Forensicator] normalizeEventLogPanels:', e); }
  try { buildEventLogBarCharts(); } catch(e) { console.error('[Forensicator] buildEventLogBarCharts:', e); }
  try { buildOverview(); } catch(e) { console.error('[Forensicator] buildOverview:', e); }
  try { renderDetections(); } catch(e) { console.error('[Forensicator] renderDetections:', e); }
  if (typeof SAMPLE_EVTLOG_DATA !== 'undefined' && Array.isArray(SAMPLE_EVTLOG_DATA) && SAMPLE_EVTLOG_DATA.length > 0) {
    renderEventLog('');
  }
  renderSimpleDetectTable(HASH_DATA, 'hash-tbody', 'hash-count');
  renderSimpleDetectTable(IOC_DATA,  'ioc-tbody',  'ioc-count');

// Init pagination first -- reads all rows, hides beyond page 1
  initPagination('det-tbody',            [1, 2, 3, 4, 5, 6],         25);
  initPagination('hash-tbody',           [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 25);
  initPagination('ioc-tbody',            [1, 2, 3, 4, 5, 6],         25);
  initPagination('users-tbody',          [0, 1, 3, 6, 7, 8],         25);
  initPagination('admins-tbody',         [0, 1, 2],                  25);
  initPagination('groups-tbody',         [0, 1, 2, 3],               25);
  initPagination('sessions-tbody',       [0, 1, 2, 3, 4],            25);
  initPagination('history-tbody',        [0, 1, 2],                  25);
  initPagination('drives-tbody',         [0, 1, 2, 3, 4],            25);
  initPagination('env-tbody',            [0, 1],                     25);
  initPagination('hotfix-tbody',         [0, 1, 2, 3, 4, 5],         25);
  initPagination('software-tbody',       [0, 1, 2, 3, 4, 5],         25);
  initPagination('defender-tbody',       [0, 1, 2, 3, 4, 5, 6, 7],   25);
  initPagination('procs-tbody',          [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 25);
  initPagination('startup-tbody',        [0, 1, 2, 3],               25);
  initPagination('net-tbody',            [0, 1, 2, 3, 4, 5, 6],      25);
  initPagination('listen-tbody',         [0, 1, 2, 3],               25);
  initPagination('dns-tbody',            [0, 1, 2, 3, 4],            25);
  initPagination('ipconfig-tbody',       [0, 1, 2, 3, 4, 5],         25);
  initPagination('net-ip-tbody',         [0, 1, 2, 3, 4],            25);
  initPagination('net-profile-tbody',    [0, 1, 2, 3, 4],            25);
  initPagination('net-adapter-tbody',    [0, 1, 2, 3, 4],            25);
  initPagination('neighbor-tbody',       [0, 1, 2],                  25);
  initPagination('wlan-tbody',           [0, 1],                     25);
  initPagination('shares-tbody',         [0, 1, 2],                  25);
  initPagination('network-adapter-tbody',[0, 1, 2, 3, 4, 5, 6, 7],   25);
  initPagination('firewall-tbody',       [0, 1, 2, 3, 4, 5, 6, 7],   25);
  initPagination('outbound-smb-tbody',   [0, 1, 2, 3, 4, 5, 6],      25);
  initPagination('smb-sessions-tbody',   [0, 1, 2, 3],               25);
  initPagination('net-hops-tbody',       [0, 1, 2, 3, 4, 5],         25);
  initPagination('adapter-hops-tbody',   [0, 1, 2, 3, 4, 5],         25);
  initPagination('ip-hops-tbody',        [0, 1, 2, 3, 4, 5],         25);
  initPagination('svc-tbody',            [0, 1, 2, 3, 4],            25);
  initPagination('tasks-tbody',          [0, 1, 2, 3],               25);
  initPagination('browser-tbody',        [0, 1, 2, 3],               25);
  initPagination('usb-tbody',            [0, 1, 2, 3],               25);
  initPagination('image-tbody',          [0, 1, 2, 3],               25);
  initPagination('upnp-tbody',           [0, 1, 2, 3],               25);
  initPagination('unknown-drives-tbody', [0, 1, 2, 3],               25);
  initPagination('files-tbody',          [0, 1, 2],                  50);
  initPagination('links-tbody',          [0, 1, 2, 3, 4],            50);
  initPagination('downloads-tbody',      [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-1-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-2-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-3-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('hidden-4-tbody',       [0, 1, 2, 3, 4, 5],         50);
  initPagination('ps-history-tbody',     [0, 1],                     50);
  initPagination('bitlocker-tbody',      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 50);
  initPagination('extras-tbody',         [0, 1, 3, 4],               25);

  // Sync count badges after pagination (querySelectorAll counts ALL rows, incl. hidden)
  syncCount('users-tbody',         'users-count');
  syncCount('admins-tbody',        'admins-count');
  syncCount('groups-tbody',        'groups-count');
  syncCount('sessions-tbody',      'sessions-count');
  syncCount('history-tbody',       'history-count');
  syncCount('software-tbody',      'software-count');
  syncCount('defender-tbody',      'defender-count');
  syncCount('procs-tbody',         'procs-count');
  syncCount('startup-tbody',       'startup-count');
  syncCount('net-tbody',           'net-count');
  syncCount('svc-tbody',           'svc-count');
  syncCount('tasks-tbody',         'tasks-count');
  syncCount('browser-tbody',       'browser-count');
  syncCount('usb-tbody',           'usb-count');
  syncCount('image-tbody',         'image-count');
  syncCount('upnp-tbody',          'upnp-count');
  syncCount('unknown-drives-tbody','unknown-drives-count');
  syncCount('files-tbody',         'files-count');
  syncCount('links-tbody',         'links-count');
  syncCount('downloads-tbody',     'downloads-count');
  syncCount('hidden-1-tbody',      'hidden-1-count');
  syncCount('hidden-2-tbody',      'hidden-2-count');
  syncCount('hidden-3-tbody',      'hidden-3-count');
  syncCount('hidden-4-tbody',      'hidden-4-count');
  syncCount('ps-history-tbody',    'ps-history-count');
  syncCount('bitlocker-tbody',     'bitlocker-count');
  syncCount('extras-tbody',        'extras-count');
  syncCount('hash-tbody',          'hash-count');
  syncCount('ioc-tbody',           'ioc-count');
  syncNetworkCards();

});

