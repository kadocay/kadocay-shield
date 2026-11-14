// Kadocay Shield — Wallet Security Scanner Agent (Wildcard track, Agent Games)
// A public agent that screens a wallet for drain / scam risk BEFORE the owner
// signs anything. BSC first (chainId 56). Node.js stdlib only, no dependencies.
//
// Endpoints:
//   GET  /        -> agent info
//   GET  /health  -> { ok: true }
//   POST /scan    -> { address, chainId? } -> risk report (JSON)
//
// Checks (all live, on-chain):
//   1. EIP-7702 delegation — eth_getCode starting 0xef0100 means the EOA
//      delegated execution to a contract. A real drain vector if unexpected.
//   2. Native BNB balance — below 0.001 BNB the wallet cannot pay gas to
//      rescue funds.
//   3. Transaction count — activity baseline.
const http = require('http');
const PORT = process.env.PORT || 8080;

const RPCS = [
  'https://bsc-dataseed.binance.org',
  'https://bsc-dataseed1.defibit.io',
  'https://bsc.publicnode.com',
];

function isAddr(a) { return /^0x[0-9a-fA-F]{40}$/.test(a || ''); }
function hexToBig(h) { try { return BigInt(h); } catch { return 0n; } }

async function rpc(url, method, params) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(8000),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message || 'rpc error');
  return j.result;
}

async function rpcAny(method, params) {
  let last;
  for (const u of RPCS) {
    try { return await rpc(u, method, params); } catch (e) { last = e; }
  }
  throw last || new Error('all rpcs failed');
}

async function scan(address, chainId) {
  const findings = [];
  const code = await rpcAny('eth_getCode', [address, 'latest']);
  const delegated = typeof code === 'string' && code.toLowerCase().startsWith('0xef0100');
  findings.push({
    check: 'eip7702_delegation', pass: !delegated, severity: delegated ? 'high' : 'info',
    detail: delegated
      ? 'Wallet code is an EIP-7702 delegation (0xef0100...). If you did not delegate this yourself, treat the wallet as compromised.'
      : 'No EIP-7702 delegation code on this wallet.',
  });
  const balHex = await rpcAny('eth_getBalance', [address, 'latest']);
  const balBnb = Number(hexToBig(balHex)) / 1e18;
  findings.push({
    check: 'native_balance', pass: true, severity: balBnb < 0.001 ? 'low' : 'info',
    detail: 'BNB balance ' + balBnb.toFixed(6) + ' BNB' + (balBnb < 0.001 ? ' — below gas comfort; top up before any rescue.' : ''),
  });
  const nonceHex = await rpcAny('eth_getTransactionCount', [address, 'latest']);
  findings.push({
    check: 'tx_count', pass: true, severity: 'info',
    detail: 'Transaction count ' + Number(hexToBig(nonceHex)) + '.',
  });
  const highs = findings.filter(f => f.severity === 'high').length;
  const level = highs > 0 ? 'HIGH' : (findings.some(f => f.severity === 'low') ? 'LOW' : 'CLEAR');
  return {
    agent: 'kadocay-shield', version: '1.0.0', chainId, address,
    riskLevel: level, highFindings: highs,
    summary: level === 'HIGH'
      ? 'High risk: an unexpected delegation or drain indicator was found. Do not sign anything until reviewed.'
      : level === 'LOW'
        ? 'Low risk: no drain indicator, but the wallet is low on gas. Top up BNB before acting.'
        : 'Clear: no drain indicator found on the checks run.',
    findings,
  };
}

const server = http.createServer((req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(obj));
  };
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    return send(200, {
      ok: true, agent: 'kadocay-shield', version: '1.0.0',
      description: 'Wallet security scanner — screens a wallet for drain/scam risk before signing.',
      usage: { scan: 'POST /scan { address, chainId? }' },
    });
  }
  if (req.method === 'POST' && req.url === '/scan') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1000000) req.destroy(); });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body || '{}');
        const address = parsed.address;
        const chainId = Number(parsed.chainId) || 56;
        if (!isAddr(address)) return send(400, { error: 'address must be a 0x 40-hex wallet address' });
        if (chainId !== 56) return send(400, { error: 'only chainId 56 (BSC) is supported in v1' });
        return send(200, await scan(address, chainId));
      } catch (e) { return send(500, { error: String((e && e.message) || e) }); }
    });
    return;
  }
  return send(404, { error: 'not found. Try GET / or POST /scan' });
});

server.listen(PORT, '127.0.0.1', () => console.log('kadocay-shield listening on 127.0.0.1:' + PORT));
