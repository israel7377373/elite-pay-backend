require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken'); // Adiciona JWT de volta se você quiser usá-lo depois

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CONFIGURAÇÕES DE INTEGRAÇÃO (MISTICPAY)
// ==========================================
// ⚠️ ATENÇÃO: As credenciais vêm do .env. Se não existirem, usamos os valores fixos de DEV.
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';
const IP_SEGURO_ADMIN = process.env.ADMIN_IP || '201.19.113.159'; // 🔒 SEU IP REAL

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÕES DE SUPORTE (SEGURANÇA E ID)
// ==========================================

// 1. PEGAR IP (PROTEÇÃO CONTRA PROXIES)
const getIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (Array.isArray(ip)) ip = ip[0];
    if (typeof ip === 'string' && ip.includes(',')) ip = ip.split(',')[0]; 
    if (typeof ip === 'string') return ip.trim().replace('::ffff:', '');
    return '';
};

// 2. IDENTIFICAR QUEM ESTÁ LOGADO (COMPATÍVEL COM 'Bearer TOKEN_FIXO_')
const getUserFromToken = (req) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

    const token = authHeader.split(' ')[1];

    // Token especial do Admin
    if (token === 'ADMIN_TOKEN_SECURE') {
        return db.users.find(u => u.role === 'admin');
    }

    // Token dos clientes (Padrão: TOKEN_FIXO_ID ou TOKEN_ID)
    let userId = null;
    if (token.startsWith('TOKEN_FIXO_')) {
        userId = parseInt(token.replace('TOKEN_FIXO_', ''));
    } else if (token.startsWith('TOKEN_')) {
        userId = parseInt(token.replace('TOKEN_', ''));
    }
    
    if (userId) {
        return db.users.find(u => u.id === userId && u.status === 'ATIVO');
    }
    
    return null;
};

// 3. FORMATAR DADOS PARA O FRONTEND
const formatarTransacao = (dados, tipo, usuario, ip, description) => {
    // Calcula valor líquido, bruto, etc., conforme o Front-end espera
    const isDeposit = tipo === 'DEPOSITO';
    const amount = Number(dados.amount || dados.transactionAmount || 0);
    const taxaApi = 0.50; // Taxa simulada da Mistic
    const taxaElite = isDeposit ? (amount * 0.04) : 1.00;
    const taxaTotal = isDeposit ? taxaApi + taxaElite : taxaElite;
    const valorLiquido = isDeposit ? (amount - taxaTotal) : amount;
    const valorBruto = amount;
    
    return {
        id: dados.id || `tx_${Date.now()}`,
        userId: usuario ? usuario.id : 0, 
        valorLiquido: valorLiquido.toFixed(2), 
        valorBruto: valorBruto.toFixed(2), 
        taxaMinha: taxaElite.toFixed(2), 
        taxaApi: taxaApi.toFixed(2), 
        descricao: description || (isDeposit ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        status: dados.transactionState || (isDeposit ? 'pendente' : 'aprovado'), // Depósito começa pendente, Saque é aprovado aqui (simulação)
        tipo: isDeposit ? 'deposito' : 'saque',
        metodo: "PIX",
        criadoEm: dados.createdAt || new Date().toISOString()
    };
};

// ==========================================
// 🧪 BANCO DE DADOS (COM ESTATÍSTICAS)
// ==========================================
const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0, daily_stats: { transactionCount: 0, totalReceived: 0 } },
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 50000, daily_stats: { transactionCount: 2, totalReceived: 150000 } }, // R$ 500.00 de saldo
    ],
    // Histórico de transações simuladas (usando o formato que o Front espera)
    transactions: [
        { id: "1", userId: 2, valorLiquido: 150.00, valorBruto: 150.00, taxaMinha: 6.50, taxaApi: 0.50, descricao: "Depósito Inicial", status: "aprovado", tipo: "deposito", metodo: "PIX", criadoEm: new Date().toISOString() },
        { id: "2", userId: 2, valorLiquido: 50.00, valorBruto: 50.00, taxaMinha: 1.00, taxaApi: 0, descricao: "Saque Elite Pay", status: "aprovado", tipo: "saque", metodo: "PIX", criadoEm: new Date().toISOString() }
    ],
    credentials: {}, // Deixando vazio para ser gerado dinamicamente
    allowedIps: []
};

// Middleware de Autenticação Real (utiliza getUserFromToken)
const checkAuth = (req, res, next) => {
    req.user = getUserFromToken(req);
    
    if (req.user && req.user.status === 'ATIVO') {
        // Se for token do Admin ou Cliente ATIVO
        return next();
    }
    
    console.log('🚫 REQUISIÇÃO BLOQUEADA: 401 Unauthorized');
    return res.status(401).json({ error: 'Token inválido ou sessão expirada' });
};

// ==========================================
// 🚀 ROTAS DE LOGIN & CADASTRO
// ==========================================
const authRoutes = express.Router();

// LOGIN
authRoutes.post('/login', (req, res) => {
    const { email, senha, password } = req.body;
    const pass = senha || password;
    const ipAtual = getIp(req);

    // --- BLOQUEIO DE SEGURANÇA ADMIN ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        if (ipAtual !== IP_SEGURO_ADMIN) {
            return res.status(403).json({ error: 'IP não autorizado para Admin', ip_detectado: ipAtual });
        }
        const adminUser = db.users.find(u => u.role === 'admin');
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- LÓGICA DE CLIENTE ---
    const user = db.users.find(u => u.email === email && (u.password === pass));
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Sua conta está pendente de aprovação pelo administrador.' });

    // Retorna o token simples que garante a persistência (TOKEN_ID)
    res.status(200).json({ token: 'TOKEN_' + user.id, user });
});

// REGISTRO
authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { 
        id: db.users.length + 1,
        email, name, password, cpf, 
        status: 'PENDENTE', role: 'user', 
        saldoCents: 0,
        daily_stats: { transactionCount: 0, totalReceived: 0 }
    };
    db.users.push(newUser);
    res.status(201).json({ message: 'Cadastro realizado! Aguarde aprovação.', user: newUser });
});

// GET PROFILE (/me)
authRoutes.get('/me', checkAuth, (req, res) => {
    // req.user já é o usuário autenticado, buscado pelo getUserFromToken no checkAuth
    if(req.user) res.json(req.user);
    else res.status(401).json({error: 'Sessão expirada'});
});
app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (INTEGRAÇÃO REAL MISTICPAY)
// ==========================================
const txRoutes = express.Router();

// 1. CRIAR PIX (RECEBER)
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = req.user; 
    
    if (!user) return res.status(401).json({ error: 'Login necessário' });

    console.log(`🔄 Criando PIX real para ${user.name} (R$ ${amount})...`);

    try {
        const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                description: description || 'Depósito Elite Pay',
                payerName: user.name, 
                payerDocument: "000.000.000-00", // MisticPay precisa de um documento, usando placeholder
                transactionId: `tx_${Date.now()}_${user.id}` // ID único
            })
        });

        const data = await misticResponse.json();
        
        if (!misticResponse.ok) {
            console.error('❌ Erro MisticPay:', data);
            return res.status(400).json({ error: data.message || 'Erro na API de Pagamento MisticPay' });
        }

        // Salva vinculando ao ID do usuário
        const novaTx = formatarTransacao(
            { ...data, transactionState: 'pendente', amount: Number(amount), createdAt: new Date().toISOString() }, 
            'DEPOSITO', user, getIp(req), description
        );
        db.transactions.unshift(novaTx);
        
        // O Front-end espera os dados do QR Code da MisticPay
        res.json({
            qrcodeUrl: data.qrcodeUrl, 
            copyPaste: data.copyPaste,
            data: novaTx // Envia também os dados formatados
        });

    } catch (error) {
        console.error('❌ Erro de conexão:', error);
        res.status(500).json({ error: 'Erro interno ao tentar gerar PIX' });
    }
});

// 2. SAQUE (TRANSFERIR)
txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    const { amount, pixKey, pixKeyType, description } = req.body;
    const user = req.user;
    
    const txFee = 1.00; // Taxa fixa de R$ 1,00
    const totalDebit = Number(amount) + txFee;
    
    if (user.saldoCents < totalDebit * 100) {
        return res.status(402).json({ error: 'Saldo insuficiente para saque' });
    }

    console.log(`💸 Solicitando Saque real de R$ ${amount} para ${pixKey} (User: ${user.id})...`);
    
    try {
        const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/withdraw`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                pixKey: pixKey,
                pixKeyType: pixKeyType,
                description: description || 'Saque Elite Pay',
                transactionId: `out_${Date.now()}_${user.id}`
            })
        });

        const data = await misticResponse.json();
        
        if (!misticResponse.ok) {
            console.error('❌ Erro MisticPay Saque:', data);
            return res.status(400).json({ error: data.message || 'Erro na API de Saque MisticPay' });
        }
        
        // Atualiza o saldo do usuário (realiza o débito)
        user.saldoCents -= totalDebit * 100;
        
        // Salva a transação
        const novaTx = formatarTransacao(
            { ...data, amount: Number(amount), transactionState: 'aprovado', createdAt: new Date().toISOString() }, 
            'RETIRADA', user, getIp(req), description
        );
        db.transactions.unshift(novaTx);
        
        // Limpa stats diários (simulação)
        user.daily_stats = { transactionCount: 0, totalReceived: 0 }; 

        res.json({ success: true, message: 'Saque realizado', transaction: novaTx });

    } catch (error) {
        console.error('❌ Erro de conexão no saque:', error);
        res.status(500).json({ error: 'Erro interno ao tentar realizar saque' });
    }
});


// 3. LISTAR (O FILTRO MÁGICO DE PRIVACIDADE)
txRoutes.get('/', checkAuth, (req, res) => {
    const user = req.user;
    
    if (user.role === 'admin') {
        return res.json({ success: true, transactions: db.transactions });
    }

    // SE FOR CLIENTE -> VÊ APENAS AS DELE
    const minhasTransacoes = db.transactions.filter(tx => tx.userId === user.id);
    res.json({ success: true, transactions: minhasTransacoes });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS DE CREDENCIAIS (INDIVIDUAL)
// ==========================================
const credRoutes = express.Router();

credRoutes.get('/', checkAuth, (req, res) => {
    const userId = req.user.id;
    res.json(db.credentials[userId] || { hasCredentials: false });
});

credRoutes.post('/generate', checkAuth, (req, res) => {
    const userId = req.user.id;
    
    const newCreds = {
        hasCredentials: true,
        clientId: 'live_' + Math.random().toString(36).substr(2, 16),
        clientSecret: 'sk_' + Math.random().toString(36).substr(2, 32),
        createdAt: new Date().toISOString()
    };
    db.credentials[userId] = newCreds;
    res.json(newCreds);
});

credRoutes.delete('/', checkAuth, (req, res) => {
    delete db.credentials[req.user.id];
    res.json({ success: true });
});

// IPs Permitidos (Admin Only ou User Specific)
credRoutes.get('/ips', checkAuth, (req, res) => res.json({ ips: db.allowedIps }));
credRoutes.post('/ips', checkAuth, (req, res) => {
    const newIp = { id: Math.random(), ip: req.body.ip, criado_em: new Date().toISOString() };
    db.allowedIps.push(newIp);
    res.json(newIp);
});
credRoutes.delete('/ips/:id', checkAuth, (req, res) => {
    db.allowedIps = db.allowedIps.filter(i => i.id != req.params.id);
    res.json({ success: true });
});
app.use('/api/credentials', credRoutes);

// ==========================================
// 👑 ROTAS DO PAINEL ADMIN (GESTÃO DE USUÁRIOS)
// ==========================================

// Todas as rotas abaixo devem ser protegidas no Admin real.
app.get('/api/users', checkAuth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
    res.json(db.users);
});

app.put('/api/users/:id/status', checkAuth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { 
        user.status = req.body.status; 
        res.json({ success: true }); 
    } else {
        res.status(404).json({ error: 'Usuário não encontrado' });
    }
});

app.get('/api/logs', checkAuth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
    res.json([]);
});

// Inicialização
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR ELITE PAY RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 IP ADMIN SEGURO: ${IP_SEGURO_ADMIN}`);
    console.log(`✨ INTEGRAÇÃO MISTICPAY: ATIVA`);
});
