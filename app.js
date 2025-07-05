const API = 'http://localhost:7736';

document.getElementById('ping').onclick = async () => {
  const out = document.getElementById('output');
  out.textContent = '…fetching…';
  try {
    const res = await fetch(`${API}/api/biocbot`);   // calls your GET /
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = 'Error: ' + err;
  }
};
