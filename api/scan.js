// POST /api/scan — Kadocay Shield wallet security scan (BSC, chainId 56).
// Vercel serverless function. Node.js stdlib only (uses global fetch).
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

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST /api/scan with { address, chainId? }' });
  }
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const address = body.address;
    const chainId = Number(body.chainId) || 56;
    if (!isAddr(address)) return res.status(400).json({ error: 'address must be a 0x 40-hex wallet address' });
    if (chainId !== 56) return res.status(400).json({ error: 'only chainId 56 (BSC) is supported in v1' });
    return res.status(200).json(await scan(address, chainId));
  } catch (e) {
    return res.status(500).json({ error: String((e && e.message) || e) });
  }
}
