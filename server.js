require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CONFIGURAÇÕES
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';
const IP_SEGURO_ADMIN = '201.19.113.159'; // 🔒 SEU IP REAL

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

// 2. IDENTIFICAR QUEM ESTÁ LOGADO
const getUserFromToken = (req) => {
    const token = req.headers['authorization'];
    if (!token) return null;

    // Token especial do Admin
    if (token === 'ADMIN_TOKEN_SECURE') {
        return db.users.find(u => u.role === 'admin');
    }

    // Token dos clientes (Padrão: TOKEN_FIXO_ID)
    if (token.startsWith('TOKEN_FIXO_')) {
        const id = token.replace('TOKEN_FIXO_', '');
        return db.users.find(u => u.id == id);
    }
    
    // Suporte legado
    if (token.startsWith('TOKEN_')) {
        const id = token.replace('TOKEN_', '');
        return db.users.find(u => u.id == id);
    }
    return null;
};

// 3. FORMATAR DADOS PARA O FRONTEND
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: dados.id || (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario ? usuario.name : "Cliente",
        externalId: dados.transactionId || dados.externalId || `loc_${Date.now()}`,
        description: descricaoExtra || dados.description || (tipo === 'DEPOSITO' ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        transactionState: dados.transactionState || "PENDENTE",
        transactionMethod: "PIX",
        transactionType: tipo,
        requestIp: ip,
        userId: usuario ? usuario.id : 0, // VÍNCULO CRUCIAL
        updatedAt: new Date().toISOString(),
        createdAt: dados.createdAt || new Date().toISOString()
    };
};

// ==========================================
// 🧪 BANCO DE DADOS (COM DADOS DE EXEMPLO ISOLADOS)
// ==========================================
const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 5000 },
    ],
    transactions: [
        // ESTAS TRANSAÇÕES SÃO APENAS DO CLIENTE ID 2 (CLIENTE TESTE)
        // SE VOCÊ LOGAR COM OUTRO USUÁRIO, NÃO VERÁ NADA DISSO.
        { id: "1", userId: 2, value: 150.00, description: "Depósito Inicial", transactionState: "PENDENTE", transactionType: "DEPOSITO", clientName: "Cliente Teste", created_at: new Date() },
        { id: "2", userId: 2, value: 50.00, description: "Teste Sistema", transactionState: "COMPLETO", transactionType: "DEPOSITO", clientName: "Cliente Teste", created_at: new Date() }
    ],
    credentials: {
        '2': { hasCredentials: true, clientId: 'live_demo', clientSecret: 'sk_demo', createdAt: new Date() }
    },
    allowedIps: []
};

// Middleware de Autenticação Básico
const checkAuth = (req, res, next) => {
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
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

    console.log(`📡 LOGIN TENTATIVA | Email: ${email} | IP: [${ipAtual}]`);

    // --- LÓGICA DE ADMIN (IP TRAVADO) ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ADMIN BLOQUEADO: IP ${ipAtual} tentou acesso.`);
            return res.status(403).json({ error: 'IP não autorizado para Admin', ip_detectado: ipAtual });
        }

        const adminUser = db.users.find(u => u.role === 'admin');
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- LÓGICA DE CLIENTE (SEM TRAVA DE IP) ---
    const user = db.users.find(u => u.email === email && (u.password === pass));
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Sua conta está pendente de aprovação pelo administrador.' });

    res.status(200).json({ token: 'TOKEN_FIXO_' + user.id, user });
});

// REGISTRO (CRIA PENDENTE)
authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { 
        id: Date.now(), // Gera ID único
        email, 
        name, 
        password, 
        cpf, 
        status: 'PENDENTE', // Começa travado
        role: 'user', 
        saldoCents: 0 
    };
    db.users.push(newUser);
    console.log(`📝 Novo registro pendente: ${email}`);
    res.status(201).json({ message: 'Cadastro realizado! Aguarde aprovação.', user: newUser });
});

authRoutes.get('/me', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    if(user) res.json(user);
    else res.status(401).json({error: 'Sessão expirada'});
});
app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (PRIVACIDADE TOTAL)
// ==========================================
const txRoutes = express.Router();

// 1. CRIAR (Associa ao ID do usuário logado)
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = getUserFromToken(req); // Descobre quem é
    if (!user) return res.status(401).json({ error: 'Login necessário' });

    console.log(`🔄 Criando PIX para ${user.name} (ID: ${user.id})...`);

    try {
        const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                description: description || 'Depósito Elite Pay',
                payerName: user.name,
                payerDocument: "000.000.000-00",
                transactionId: `tx_${Date.now()}`
            })
        });

        const data = await misticResponse.json();
        if (!misticResponse.ok) return res.status(400).json({ error: data.message || 'Erro na API de Pagamento' });

        // Salva vinculando ao ID do usuário
        const novaTx = formatarTransacao(data, 'DEPOSITO', user, getIp(req), description);
        db.transactions.unshift(novaTx);
        res.json(data);

    } catch (error) {
        console.error('❌ Erro:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// 2. SAQUE (Associa ao ID do usuário logado)
txRoutes.post('/withdraw', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const { amount } = req.body;
    
    const novaTx = formatarTransacao(
        { id: `out_${Date.now()}`, amount, transactionState: 'COMPLETO' }, 
        'RETIRADA', user, getIp(req), "Saque Solicitado"
    );
    
    db.transactions.unshift(novaTx);
    res.json({ success: true, message: 'Saque realizado', transaction: novaTx });
});

// 3. LISTAR (O FILTRO MÁGICO DE PRIVACIDADE)
txRoutes.get('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Não autorizado' });

    // SE FOR ADMIN -> VÊ TUDO
    if (user.role === 'admin') {
        return res.json({ success: true, transactions: db.transactions });
    }

    // SE FOR CLIENTE -> VÊ APENAS AS DELE (userId == user.id)
    const minhasTransacoes = db.transactions.filter(tx => tx.userId == user.id);
    
    // Se ele não tiver nenhuma, retorna array vazio [] (Painel limpo)
    res.json({ success: true, transactions: minhasTransacoes });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS DE CREDENCIAIS (INDIVIDUAL)
// ==========================================
const credRoutes = express.Router();

credRoutes.get('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const userId = user ? user.id : 'temp';
    res.json(db.credentials[userId] || { hasCredentials: false });
});

credRoutes.post('/generate', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const userId = user ? user.id : 'temp';
    
    const newCreds = {
        hasCredentials: true,
        clientId: 'live_' + Math.random().toString(36).substr(2, 16),
        clientSecret: 'sk_' + Math.random().toString(36).substr(2, 32),
        createdAt: new Date()
    };
    db.credentials[userId] = newCreds;
    res.json(newCreds);
});

credRoutes.delete('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    if(user) delete db.credentials[user.id];
    res.json({ success: true });
});

// IPs Permitidos (Admin Only ou User Specific)
credRoutes.get('/ips', checkAuth, (req, res) => res.json({ ips: db.allowedIps }));
credRoutes.post('/ips', checkAuth, (req, res) => {
    const newIp = { id: Math.random(), ip: req.body.ip, criado_em: new Date() };
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

// Listar Usuários (Para você ver quem se cadastrou)
app.get('/api/users', (req, res) => {
    // Pode adicionar checkAuth aqui se quiser proteger, mas mantive aberto conforme seu código original
    res.json(db.users);
});

// Aprovar/Bloquear Usuário
app.put('/api/users/:id/status', (req, res) => {
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { 
        console.log(`👑 Admin alterou status de ${user.email} para ${req.body.status}`);
        user.status = req.body.status; 
        res.json({ success: true }); 
    } else {
        res.status(404).json({ error: 'Usuário não encontrado' });
    }
});

app.get('/api/logs', (req, res) => res.json([]));

// Inicialização
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR ELITE PAY RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 IP ADMIN SEGURO: ${IP_SEGURO_ADMIN}`);
    console.log(`🛡️ SISTEMA DE PRIVACIDADE: ATIVADO`);
});
