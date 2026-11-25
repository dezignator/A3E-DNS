"""PyTorch detector matching Table 27 (8 layers, 12 heads, window 512) with the temporal-decay bias of
Section 6.6.1, plus PGD adversarial training (epsilon = 0.3, 50 epochs). Requires torch; not executed in
the environment that produced the v2 results (the NumPy harness uses a small MLP instead)."""
try:
    import torch, torch.nn as nn, torch.nn.functional as F
except ImportError:  # pragma: no cover
    torch = None

if torch is not None:
    class DecayEncoderLayer(nn.Module):
        def __init__(self, d, h, gamma):
            super().__init__(); self.h, self.g = h, gamma
            self.att = nn.MultiheadAttention(d, h, batch_first=True); self.ff = nn.Sequential(nn.Linear(d, 4 * d), nn.GELU(), nn.Linear(4 * d, d))
            self.n1, self.n2 = nn.LayerNorm(d), nn.LayerNorm(d)
        def forward(self, x):
            T = x.size(1); i = torch.arange(T, device=x.device); bias = -self.g * (i[:, None] - i[None, :]).abs().float()
            a, _ = self.att(x, x, x, attn_mask=bias); x = self.n1(x + a); return self.n2(x + self.ff(x))
    class A3EDetector(nn.Module):
        def __init__(self, d_in=16, d=48, layers=8, heads=12, gamma=0.05, window=512):
            super().__init__(); self.inp = nn.Linear(d_in, d); self.pos = nn.Parameter(torch.zeros(1, window, d))
            self.blocks = nn.ModuleList([DecayEncoderLayer(d, heads, gamma) for _ in range(layers)]); self.out = nn.Linear(d, 1)
        def forward(self, x):
            z = self.inp(x) + self.pos[:, : x.size(1)]
            for b in self.blocks: z = b(z)
            return self.out(z.mean(1)).squeeze(-1)
    def pgd_attack(model, x, y, eps=0.3, steps=10):
        a = 2.5 * eps / steps; xa = x.clone().detach()
        for _ in range(steps):
            xa.requires_grad_(True); loss = F.binary_cross_entropy_with_logits(model(xa), y); g, = torch.autograd.grad(loss, xa)
            xa = (xa.detach() + a * g.sign()); xa = torch.min(torch.max(xa, x - eps), x + eps)
        return xa.detach()
    def train_epoch(model, loader, opt, adv_eps=0.3):
        model.train(); tot = 0.0
        for x, y in loader:
            xa = pgd_attack(model, x, y, adv_eps); loss = 0.5 * F.binary_cross_entropy_with_logits(model(x), y) + 0.5 * F.binary_cross_entropy_with_logits(model(xa), y)
            opt.zero_grad(); loss.backward(); opt.step(); tot += loss.item()
        return tot / max(len(loader), 1)
