export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({
    ok: true, agent: 'kadocay-shield', version: '1.0.0',
    description: 'Wallet security scanner — screens a wallet for drain/scam risk before signing.',
    usage: { scan: 'POST /api/scan { address, chainId? }' },
  });
}
