require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CREDENCIAIS E CONFIGURAÇÕES DE SEGURANÇA
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv'; 
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d'; 
const MISTIC_URL = 'https://api.misticpay.com'; 

// --- CONFIGURAÇÃO DO ADMIN ---
const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';

// 🛑 IP DE SEGURANÇA MÁXIMA (SEU IP REAL)
const IP_SEGURO_ADMIN = '201.19.113.159'; 

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÕES AUXILIARES
// ==========================================

// 1. Pegar IP Real (Tratamento Robusto para Render/Proxies)
const getIp = (req) => {
    // Tenta pegar o cabeçalho do proxy (padrão do Render)
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    // Se houver múltiplos IPs (proxy chain), pega o primeiro (o do cliente real)
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }

    // Remove prefixo IPv6 que às vezes aparece (::ffff:) para garantir comparação limpa
    if (typeof ip === 'string' && ip.includes('::ffff:')) {
        ip = ip.replace('::ffff:', '');
    }

    return ip;
};

// 2. Formatar Transação
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario.name,
        clientDocument: "000.000.000-00",
        externalId: dados.transactionId || dados.externalId || dados.id || `loc_${Date.now()}`,
        description: descricaoExtra || dados.description || (tipo === 'DEPOSITO' ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        transactionState: dados.transactionState || "PENDENTE",
        transactionMethod: "PIX",
        transactionType: tipo,
        requestIp: ip,
        userId: usuario.id,
        updatedAt: new Date().toISOString(),
        createdAt: dados.createdAt || new Date().toISOString()
    };
};

// ==========================================
// 🧪 DADOS INICIAIS (BANCO DE DADOS EM MEMÓRIA)
// ==========================================

const transacoesIniciais = [
    {
        id: "1", value: 50.00, fee: 0.50, clientName: "Cliente Teste", 
        description: "Depósito Inicial", externalId: "019506c8-d275...", 
        transactionState: "PENDENTE", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date().toISOString()
    },
    {
        id: "2", value: 120.00, fee: 1.00, clientName: "Israel Roza Silva", 
        description: "Saque Elite Pay", externalId: "c73841b5-c8e3...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "RETIRADA", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date(Date.now() - 3600000).toISOString()
    }
];

const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
    ],
    transactions: [...transacoesIniciais],
    credentials: {
        '2': { hasCredentials: true, clientId: 'live_demo123', clientSecret: 'sk_demo123', createdAt: new Date() }
    },
    allowedIps: []
};

// Middleware Auth
const checkAuth = (req, res, next) => {
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
};

// ==========================================
// 🚀 ROTAS DE LOGIN (COM BLOQUEIO IP REAL)
// ==========================================
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, password, senha } = req.body;
    const pass = password || senha;
    
    // Obtém o IP limpo e tratado
    const ipAtual = getIp(req);

    console.log(`📡 LOGIN TENTATIVA | Email: ${email} | IP Detectado: [${ipAtual}]`);

    // --- LÓGICA DE ADMIN (Blindagem por IP) ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        // Verifica se o IP é EXATAMENTE o permitido
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ALERTA DE SEGURANÇA: IP ${ipAtual} tentou acessar Admin. Bloqueado.`);
            return res.status(403).json({ 
                error: 'ACESSO NEGADO: Seu IP não está autorizado para administração.',
                ip_detectado: ipAtual // Retorna o IP para você saber qual está chegando se der erro
            });
        }

        console.log(`✅ ACESSO ADMIN LIBERADO para IP: ${ipAtual}`);
        const adminUser = db.users.find(u => u.email === ADMIN_EMAIL);
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- CLIENTES (Acesso Livre de IP) ---
    const user = db.users.find(u => u.email === email && u.password === pass);
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Conta pendente' });

    res.status(200).json({ token: 'TOKEN_' + user.id, user });
});

authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { id: Date.now(), email, name, password, cpf, status: 'PENDENTE', role: 'user', saldoCents: 0 };
    db.users.push(newUser);
    res.status(201).json({ message: 'Cadastro realizado', user: newUser });
});

authRoutes.get('/me', checkAuth, (req, res) => res.json(db.users[1]));
app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO
// ==========================================
const txRoutes = express.Router();

// 1. CRIAR DEPÓSITO
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = db.users[1];
    const ip = getIp(req);

    try {
        const misticRes = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                description: description || 'Depósito Elite Pay',
                payerName: user.name,
                payerDocument: "000.000.000-00",
                transactionId: `in_${Date.now()}`
            })
        });

        const data = await misticRes.json();
        if (!misticRes.ok) return res.status(400).json({ error: data.message || 'Erro API' });

        const novaTx = formatarTransacao({ ...data, transactionState: 'PENDENTE' }, 'DEPOSITO', user, ip, description);
        db.transactions.unshift(novaTx);
        res.json(novaTx);

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

// 2. CRIAR SAQUE
txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    const { amount, pixKey, pixKeyType, description } = req.body;
    const user = db.users[1];
    const ip = getIp(req);

    if (!amount || !pixKey || !pixKeyType) return res.status(400).json({ error: "Dados incompletos" });

    try {
        const misticRes = await fetch(`${MISTIC_URL}/api/transactions/withdraw`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount), pixKey, pixKeyType,
                description: description || "Saque Elite Pay"
            })
        });

        const data = await misticRes.json();
        if (!misticRes.ok) return res.status(400).json({ error: data.message || 'Erro MisticPay' });

        const novaTx = formatarTransacao(data, 'RETIRADA', user, ip, description);
        if(!novaTx.transactionState) novaTx.transactionState = "COMPLETO";
        db.transactions.unshift(novaTx);
        res.json(novaTx);

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

txRoutes.get('/', checkAuth, (req, res) => {
    res.json({ success: true, transactions: db.transactions });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS AUXILIARES
// ==========================================
const credRoutes = express.Router();
credRoutes.get('/', checkAuth, (req, res) => res.json(db.credentials['2'] || { hasCredentials: false }));
credRoutes.post('/generate', checkAuth, (req, res) => {
    const nc = { hasCredentials: true, clientId: 'live_'+Date.now(), clientSecret: 'sk_'+Date.now(), createdAt: new Date() };
    db.credentials['2'] = nc; 
    res.json(nc);
});
credRoutes.delete('/', checkAuth, (req, res) => { delete db.credentials['2']; res.json({success:true});});
app.use('/api/credentials', credRoutes);

// Rotas Admin Simples
app.get('/api/users', (req, res) => res.json(db.users));
app.put('/api/users/:id/status', (req, res) => {
    const u = db.users.find(x => x.id == req.params.id);
    if(u) { u.status = req.body.status; res.json({success:true}); } 
    else res.status(404).json({error:'User not found'});
});

// Inicialização
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR COMPLETO RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 SEGURANÇA MÁXIMA ATIVA: Apenas IP ${IP_SEGURO_ADMIN} pode logar como Admin.`);
});
