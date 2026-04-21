function filterPkgs() {
  const q = document.getElementById('pkgSearch').value.toLowerCase();
  const eco = document.getElementById('ecoFilter') ? document.getElementById('ecoFilter').value : '';
  const lf = document.getElementById('labelFilter') ? document.getElementById('labelFilter').value : '';
  const det = document.getElementById('detFilter') ? document.getElementById('detFilter').value : '';
  document.querySelectorAll('#pkgTable .pkg-row').forEach(tr => {
    let show = true;
    if (q && tr.dataset.name.indexOf(q) === -1) show = false;
    if (eco && tr.dataset.eco !== eco) show = false;
    if (lf && tr.dataset.label !== lf) show = false;
    if (det && tr.dataset.detected !== det) show = false;
    tr.style.display = show ? '' : 'none';
  });
}
function sortTable(id, col) {
  const table = document.getElementById(id);
  const rows = Array.from(table.querySelectorAll('tr:not(:first-child)'));
  const dir = table.dataset.sortCol == col && table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
  table.dataset.sortCol = col; table.dataset.sortDir = dir;
  rows.sort((a, b) => {
    let va = a.cells[col].textContent.trim(), vb = b.cells[col].textContent.trim();
    const na = parseFloat(va.replace(/[^\d.\-]/g, '')), nb = parseFloat(vb.replace(/[^\d.\-]/g, ''));
    if (!isNaN(na) && !isNaN(nb)) { va = na; vb = nb; }
    return va < vb ? (dir === 'asc' ? -1 : 1) : va > vb ? (dir === 'asc' ? 1 : -1) : 0;
  });
  const tbody = table.tBodies[0] || table;
  rows.forEach(r => tbody.appendChild(r));
}
