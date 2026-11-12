'use strict';
let token = '', state = null, timer;
const $ = id => document.getElementById(id);
async function request(path, method = 'GET', body) {
  const response = await fetch(path, {method, headers: {'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json'}, body: body === undefined ? undefined : JSON.stringify(body)});
  if (!response.ok) { const error = await response.json(); throw new Error(error.error || response.statusText); }
  return response;
}
function cell(row, value) { const td = document.createElement('td'); td.textContent = value; row.append(td); return td; }
function flows() {
  $('flows').replaceChildren();
  const filter = $('filter').value.toLowerCase();
  for (const f of state?.telemetry?.flows || []) {
    if (!JSON.stringify(f).toLowerCase().includes(filter)) continue;
    const row = document.createElement('tr');
    for (const value of [f.direction, `${f.src}:${f.sport}`, `${f.dst}:${f.dport}`, ({6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'})[f.protocol] || f.protocol, `${f.vlan_outer ?? 'none/unknown'} / ${f.vlan_inner ?? '—'} / ${f.vni ?? '—'}`, f.packets, f.bytes]) cell(row, value);
    $('flows').append(row);
  }
}
async function refresh() {
  try {
    state = await (await request('/api/state')).json();
    $('error').textContent = '';
    $('login').hidden = true; $('dashboard').hidden = false;
    $('mode').textContent = state.config.enforce ? 'Enforcement requested' : 'Observation requested';
    $('status').textContent = `Desired revision ${state.revision} · Applied ${state.status.applied}` + (state.status.error ? ` · Agent error: ${state.status.error}` : '') + (state.telemetry.error ? ` · Telemetry unavailable: ${state.telemetry.error}` : '');
    if (!document.querySelector('#config:focus-within')) {
      $('enforce').checked = state.config.enforce; $('udp').value = state.config.udp_pps_cpu; $('syn').value = state.config.syn_pps_cpu;
    }
    $('cards').replaceChildren();
    for (const [name, value] of [['Ingress passed',state.telemetry.stats?.['0']?.packets ?? '—'],['Actually dropped',state.telemetry.stats?.['8']?.packets ?? '—'],['Egress observed',state.telemetry.stats?.['4']?.packets ?? '—'],['Active flow records',state.telemetry.active_records ?? '—']]) {
      const box = document.createElement('div'); const label = document.createElement('span'); label.textContent = name; const number = document.createElement('strong'); number.textContent = value; box.append(label, number); $('cards').append(box);
    }
    $('rules').replaceChildren();
    for (const rule of state.rules) {
      const row = document.createElement('tr'); cell(row, rule.cidr); cell(row, rule.reason); cell(row, rule.expires_at ? new Date(rule.expires_at * 1000).toLocaleString() : 'Permanent');
      const button = document.createElement('button'); button.textContent = 'Remove'; button.onclick = () => action(`/api/rules/${rule.id}`, 'DELETE'); cell(row, '').append(button); $('rules').append(row);
    }
    $('audit').replaceChildren();
    for (const entry of state.audit) { const p = document.createElement('p'); p.textContent = `${new Date(entry.ts * 1000).toLocaleString()} · ${entry.action} · ${entry.details}`; $('audit').append(p); }
    for (const id of ['connections','sockets','history']) $(id).replaceChildren();
    for (const c of state.telemetry.connections || []) {
      const row = document.createElement('tr');
      for (const value of [c.endpoint_a.join(':'),c.endpoint_b.join(':'),c.protocol,`${c.vlan_outer ?? 'none/unknown'} / ${c.vni ?? '—'}`,c.state,c.bytes]) cell(row,value);
      $('connections').append(row);
    }
    for (const c of state.telemetry.local_sockets || []) {
      const row = document.createElement('tr');
      for (const value of [`${c.src}:${c.sport}`,`${c.dst}:${c.dport}`,c.state]) cell(row,value);
      $('sockets').append(row);
    }
    for (const sample of (state.history || []).slice(0,12)) {
      const counts = JSON.parse(sample.counters); const row = document.createElement('tr');
      cell(row,new Date(sample.ts * 1000).toLocaleTimeString());
      for (const id of ['0','1','5','6']) cell(row,counts[id]?.packets ?? 0);
      $('history').append(row);
    }
    flows();
  } catch (e) { $('error').textContent = e.message; }
}
async function action(path, method, body) { try { await request(path, method, body); await refresh(); } catch (e) { $('error').textContent = e.message; } }
$('auth').onsubmit = e => { e.preventDefault(); token = $('token').value; $('token').value = ''; refresh(); clearInterval(timer); timer = setInterval(refresh, 5000); };
$('rule').onsubmit = e => { e.preventDefault(); action('/api/rules', 'POST', {cidr:$('cidr').value, reason:$('reason').value, ttl_seconds:Number($('ttl').value)}); };
$('config').onsubmit = e => { e.preventDefault(); action('/api/config', 'POST', {enforce:$('enforce').checked, udp_pps_cpu:Number($('udp').value), syn_pps_cpu:Number($('syn').value)}); };
$('refresh').onclick = refresh;
$('filter').oninput = flows;
$('logout').onclick = () => { clearInterval(timer); token = ''; state = null; $('dashboard').hidden = true; $('login').hidden = false; $('mode').textContent = 'Disconnected'; };
$('export').onclick = async () => { try { const response = await request('/api/report.csv'); const url = URL.createObjectURL(await response.blob()); const link = document.createElement('a'); link.href = url; link.download = 'firewall-audit.csv'; link.click(); URL.revokeObjectURL(url); } catch(e) { $('error').textContent = e.message; } };
