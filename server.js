require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// --- SUAS CREDENCIAIS REAIS (FALLBACK) ---
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());

// --- DADOS MOCK (Login Simples) ---
const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
        { id: 2, email: 'cliente@pay.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 5000 }
    ],
    transactions: [] 
};

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
const checkAuth = (req, res, next) => {
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
};

// --- ROTAS DE LOGIN ---
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, senha } = req.body;
    const user = db.users.find(u => u.email === email && (u.password === senha || u.password === req.body.password));
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Conta pendente' });

    res.status(200).json({ token: 'TOKEN_FIXO_' + user.id, user });
});

authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { id: Date.now(), email, name, password, cpf, status: 'PENDENTE', role: 'user', saldoCents: 0 };
    db.users.push(newUser);
    res.status(201).json({ message: 'Cadastro realizado', user: newUser });
});

authRoutes.get('/me', checkAuth, (req, res) => res.json(db.users[1]));
app.use('/api/auth', authRoutes);

// --- ROTAS DE TRANSAÇÃO ---
const txRoutes = express.Router();

// 1. CRIAR DEPÓSITO (CORRIGIDO: REMOVIDO O SPLIT)
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;

    console.log(`🔄 [Backend] Gerando PIX de R$ ${amount}...`);

    try {
        const payload = {
            amount: Number(amount),
            description: description || 'Depósito via Elite Pay',
            payerName: "Cliente Teste", 
            payerDocument: "000.000.000-00",
            transactionId: `tx_${Date.now()}`
            // REMOVIDO: splitTax: "0" -> ISSO CAUSAVA O ERRO!
        };

        const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'ci': MISTIC_CI,
                'cs': MISTIC_CS
            },
            body: JSON.stringify(payload)
        });

        const data = await misticResponse.json();

        if (!misticResponse.ok) {
            console.error('❌ Erro MisticPay:', data);
            return res.status(400).json({ error: data.message || 'Erro na MisticPay' });
        }

        console.log('✅ QR Code gerado com sucesso!');
        
        db.transactions.push({ ...data, created_at: new Date() });
        res.json(data);

    } catch (error) {
        console.error('❌ Erro de conexão:', error);
        res.status(500).json({ error: 'Falha ao conectar com provedor de pagamento' });
    }
});

// 2. Listar Transações
txRoutes.get('/', checkAuth, (req, res) => {
    res.json({ success: true, transactions: db.transactions });
});

// 3. Saque
txRoutes.post('/withdraw', checkAuth, (req, res) => {
    res.json({ success: true, message: 'Saque solicitado' });
});

app.use('/api/transactions', txRoutes);

// --- ROTAS DO ADMIN ---
app.get('/api/users', (req, res) => res.json(db.users));
app.get('/api/logs', (req, res) => res.json([]));
app.put('/api/users/:id/status', (req, res) => {
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { user.status = req.body.status; res.json({ success: true }); }
    else res.status(404).json({ error: 'User not found' });
});

app.listen(PORT, () => {
    console.log(`✅ Servidor Rodando na porta ${PORT}`);
});