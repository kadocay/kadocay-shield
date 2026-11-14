export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({ ok: true, agent: 'kadocay-shield', version: '1.0.0' });
}
