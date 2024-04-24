import numpy as np
import torch


def check_size(x, coef):
    if isinstance(coef, (int, float)):
        return coef
    elif isinstance(coef, dict):
        for k, v in coef.items():
            if isinstance(v, torch.Tensor):
                while len(v.shape) < len(x.shape):
                    v = v.unsqueeze(-1)
                coef[k] = v
    elif isinstance(coef, torch.Tensor):
        while len(coef.shape) < len(x.shape):
            coef = coef.unsqueeze(-1)
    return coef


class BaseNoiser(torch.nn.Module):
    def __init__(self, args, device):
        super().__init__()
        self.args = args
        self.device = device

        self.training_timesteps = self.args.training_timesteps
        self.training_timestep_map = torch.arange(start=0, end=self.training_timesteps, step=1, dtype=torch.int64, device=self.device)
        self.inference_timesteps = self.args.inference_timesteps
        self.inference_timestep_map = torch.arange(start=0, end=self.training_timesteps, step=int(self.training_timesteps / self.inference_timesteps), dtype=torch.int64, device=self.device)

        self.num_timesteps = self.training_timesteps
        self.timestep_map = self.training_timestep_map

    def train(self, mode=True):
        self.num_timesteps = self.training_timesteps if mode else self.inference_timesteps
        self.timestep_map = self.training_timestep_map if mode else self.inference_timestep_map
    
    def eval(self):
        self.train(mode=False)
    
    def coefficient(self, t):
        raise NotImplementedError

    def forward(self, x_0, x_1, t, ode=True):
        coef = check_size(x_0, self.coefficient(t))
        x_t = coef['coef0'] * x_0 + coef['coef1'] * x_1
        if 'var' in coef and not ode:
            x_t = x_t + torch.randn_like(x_t) * coef['var'] ** 0.5
        return x_t

    def trajectory(self, x_0, x_1, ode=True):
        x_all = [x_0.clone()]
        with torch.no_grad():
            for t in range(self.num_timesteps):
                x_t = self.forward(x_0, x_1, t, ode)
                x_all.append(x_t.clone())
        x_all = torch.stack(x_all, dim=0)
        return x_all

    def forward_dsb(self, x, x_0, x_1, t):
        coef_t = check_size(x, self.coefficient(t))
        coef_t_plus_one = check_size(x, self.coefficient(t + 1))
        x = x_0 + (x - x_0) / coef_t_plus_one['coef1'] * coef_t['coef1']
        return x
    
    def prepare_gamma_dsb(self):
        if hasattr(self, 'gammas'):
            return
        if self.args.gamma_type == "linear":
            gamma_max = 0.1
            gamma_min = 0.0001
            # linearly gamma_min -> gamma_max -> gamma_min
            self.gammas = torch.linspace(gamma_min, gamma_max, self.num_timesteps // 2, device=self.device)
            self.gammas = torch.cat([self.gammas, self.gammas.flip(dims=(0,))], dim=0)
        elif self.args.gamma_type.startswith("linear_"):
            gamma_min = float(self.args.gamma_type.split("_")[1])
            gamma_max = float(self.args.gamma_type.split("_")[2])
            # linearly gamma_min -> gamma_max -> gamma_min
            self.gammas = torch.linspace(gamma_min, gamma_max, self.num_timesteps // 2, device=self.device)
            self.gammas = torch.cat([self.gammas, self.gammas.flip(dims=(0,))], dim=0)
        elif self.args.gamma_type == "constant":
            self.gammas = 0.0005 * torch.ones(size=(self.num_timesteps,), dtype=torch.float32, device=self.device)
        elif self.args.gamma_type.startswith("constant_"):
            gamma = float(self.args.gamma_type.split("_")[1])
            self.gammas = gamma * torch.ones(size=(self.num_timesteps,), dtype=torch.float32, device=self.device)
        else:
            raise NotImplementedError(f"gamma_type {self.args.gamma_type} not implemented")

    def trajectory_dsb(self, x_0, x_1, sample=False):
        self.prepare_gamma_dsb()
        ones = torch.ones(size=(x_0.shape[0],), dtype=torch.int64, device=self.device)
        x_cache, gt_cache, t_cache = [], [], []
        x = x_1
        with torch.no_grad():
            for t in range(self.num_timesteps - 1, -1, -1):
                x_old = x.clone()
                t_old = self.forward_dsb(x, x_0, x_1, ones * t)
                if sample and t == 0:
                    x = t_old
                else:
                    x = t_old + torch.sqrt(2 * self.gammas[t]) * torch.randn_like(x)
                x_cache.append(x.clone())
                if self.args.simplify:
                    if self.args.reparam == 'flow':
                        gt_cache.append((x_1 - x) / (1 - t / self.num_timesteps))
                    elif self.args.reparam == 'term':
                        gt_cache.append(x_1)
                    else:
                        gt_cache.append(x_old)
                else:
                    t_new = self.forward_dsb(x, x_0, x_1, ones * t)
                    gt_cache.append(x + t_old - t_new)
                t_cache.append(ones * t)
        x_cache = torch.stack([x_1] + x_cache, dim=0).cpu() if sample else torch.cat(x_cache, dim=0).cpu()
        gt_cache = torch.cat(gt_cache, dim=0).cpu()
        t_cache = torch.cat(t_cache, dim=0).cpu()
        return x_cache, gt_cache, t_cache


class FlowNoiser(BaseNoiser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def coefficient(self, t):
        tmax = t.max() if isinstance(t, torch.Tensor) else t
        if tmax >= len(self.timestep_map):
            ret = {
                'coef0': 0,
                'coef1': 1,
            }
        else:
            t = self.timestep_map[t].float()
            ret = {
                'coef0': 1 - t / self.training_timesteps,
                'coef1': t / self.training_timesteps,
            }
        ret = {k: v.float() if isinstance(v, torch.Tensor) else v for k, v in ret.items()}
        return ret


class LinearNoiser(BaseNoiser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        beta_start, beta_end = 0.0001, 0.02

        betas = torch.linspace(beta_start, beta_end, self.num_timesteps, dtype=torch.float64, device=self.device)
        alphas = 1.0 - betas
        alphas_cumprod = torch.cumprod(alphas, dim=0)
        self.sqrt_alphas_cumprod = torch.sqrt(alphas_cumprod)
        self.sqrt_one_minus_alphas_cumprod = torch.sqrt(1.0 - alphas_cumprod)

    def coefficient(self, t):
        tmax = t.max() if isinstance(t, torch.Tensor) else t
        if tmax >= len(self.timestep_map):   
            ret = {
                'coef0': 0,
                'coef1': 1,
            }
        else:
            t = self.timestep_map.flip(dims=(0,))[t]
            ret = {
                'coef0': self.sqrt_one_minus_alphas_cumprod[t],
                'coef1': self.sqrt_alphas_cumprod[t],
            }
        ret = {k: v.float() if isinstance(v, torch.Tensor) else v for k, v in ret.items()}
        return ret


class EDMNoiser(BaseNoiser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        sigma_min, sigma_max, rho = 0.002, 80, 7
        step_indices = torch.arange(self.num_timesteps, dtype=torch.float64, device=self.device)
        t_steps = (sigma_max ** (1 / rho) + step_indices / (self.num_timesteps - 1) * (sigma_min ** (1 / rho) - sigma_max ** (1 / rho))) ** rho
        self.t_steps = torch.cat([torch.as_tensor(t_steps), torch.zeros_like(t_steps[:1])]) # t_N = 0
        #self.t_hats = torch.from_numpy(np.load('t_hats_tensor.npy')).to(device='cuda')
        #self.st_noises = torch.from_numpy(np.load('st_noises_tensor.npy')).to(device='cuda')

        self.S_churn, self.S_min, self.S_max, self.S_noise = 30, 0, float('inf'), 1.007
    
    def add_noise(self, x, t, i):
        t = t.reshape(-1, 1, 1, 1)

        cond = torch.logical_and(self.S_min <= t, t <= self.S_max)
        var = min(self.S_churn / self.num_timesteps, np.sqrt(2) - 1)
        gamma = torch.where(cond, torch.ones_like(t) * var, torch.zeros_like(t))
        t_hat = torch.as_tensor(t + gamma * t)
        x_hat = x + (t_hat ** 2 - t ** 2).sqrt() * self.S_noise * torch.randn_like(x)
        return x_hat, t_hat

    def coefficient(self, t):
        last_idx = torch.ones_like(t) * len(self.timestep_map) - 1
        t = torch.where(t >= len(self.timestep_map), last_idx, t)
        t =  self.timestep_map[t].int()
        return self.t_steps[t]

class DSBNoiser(BaseNoiser):
    def __init__(self, *args, mean=0, std=1, **kwargs):
        super().__init__(*args, **kwargs)

        self.mean, self.var = mean, std ** 2

        self.prepare_gamma_dsb()
    
    def forward(self, x, t):
        x = x + self.gammas[t] * (self.mean - x) / self.var
        return x

    def trajectory(self, x_0, x_1, sample=False):
        ones = torch.ones(size=(self.args.batch_size,), dtype=torch.int64, device=self.device)
        x_cache, gt_cache, t_cache = [], [], []
        x = x_1
        with torch.no_grad():
            for t in range(self.num_timesteps):
                x_old = x.clone()
                t_old = self.forward(x, t)
                if sample and t == self.num_timesteps - 1:
                    x = t_old
                else:
                    x = t_old + torch.sqrt(2 * self.gammas[t]) * torch.randn_like(x)
                x_cache.append(x.clone())
                if self.args.simplify:
                    if self.args.reparam == 'flow':
                        gt_cache.append((x_1 - x) / (1 - t / self.num_timesteps))
                    elif self.args.reparam == 'term':
                        gt_cache.append(x_1)
                    else:
                        gt_cache.append(x_old)
                else:
                    t_new = self.forward(x, t)
                    gt_cache.append(x + t_old - t_new)
                t_cache.append(ones * (self.num_timesteps - 1 - t))
        if sample:
            x_cache = torch.stack([x_1] + x_cache, dim=0).cpu()
        else:
            x_cache = torch.cat(x_cache, dim=0).cpu()
        gt_cache = torch.cat(gt_cache, dim=0).cpu()
        t_cache = torch.cat(t_cache, dim=0).cpu()
        return x_cache, gt_cache, t_cache

    def trajectory_dsb(self, x_0, x_1, sample=False):
        return self.trajectory(x_0, x_1, sample=sample)


def create_noiser(name, *args, **kwargs):
    name = name.lower()
    if 'flow' in name:
        noiser = FlowNoiser
    elif 'linear' in name:
        noiser = LinearNoiser
    elif 'dsb' in name:
        noiser = DSBNoiser
    elif 'edm' in name:
        noiser = EDMNoiser
    else:
        raise NotImplementedError
    return noiser(*args, **kwargs)
