require(‘dotenv’).config();
const express = require(‘express’);
const cors = require(‘cors’);
const bodyParser = require(‘body-parser’);

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CONFIGURAÇÕES DE INTEGRAÇÃO (MISTICPAY)
// ==========================================
// ⚠️ CREDENCIAIS FORNECIDAS PELO USUÁRIO (MisticPay)
const MISTIC_CI = ‘ci_jbbmajuwwmq28hv’;
const MISTIC_CS = ‘cs_isxps89xg5jodulumlayuy40d’;
const MISTIC_URL = ‘https://api.misticpay.com’;

const ADMIN_EMAIL = ‘admin@pay.com’;
const ADMIN_PASS = ‘admin’;
const IP_SEGURO_ADMIN = process.env.ADMIN_IP || ‘201.19.113.159’; // 🔒 SEU IP REAL

app.use(cors({ origin: ‘*’, methods: [‘GET’, ‘POST’, ‘PUT’, ‘DELETE’, ‘OPTIONS’], allowedHeaders: [‘Content-Type’, ‘Authorization’] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÕES DE SUPORTE
// ==========================================

const getIp = (req) => {
let ip = req.headers[‘x-forwarded-for’] || req.socket.remoteAddress || ‘’;
if (Array.isArray(ip)) ip = ip[0];
if (typeof ip === ‘string’ && ip.includes(’,’)) ip = ip.split(’,’)[0];
if (typeof ip === ‘string’) return ip.trim().replace(’::ffff:’, ‘’);
return ‘’;
};

const getUserFromToken = (req) => {
const authHeader = req.headers[‘authorization’];
if (!authHeader || !authHeader.startsWith(’Bearer ’)) return null;

```
const token = authHeader.split(' ')[1];

if (token === 'ADMIN_TOKEN_SECURE') {
    return db.users.find(u => u.role === 'admin');
}

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
```

};

const formatarTransacao = (dados, tipo, usuario, ip, description) => {
const isDeposit = tipo === ‘DEPOSITO’;
const amount = Number(dados.amount || dados.transactionAmount || 0);

```
const taxaApi = 0.50;
const taxaElite = isDeposit ? (amount * 0.04) : 1.00;
const taxaTotal = isDeposit ? taxaApi + taxaElite : taxaElite;
const valorLiquido = isDeposit ? (amount - taxaTotal) : amount;
const valorBruto = amount;

return {
    id: dados.transactionId || `tx_${Date.now()}`,
    userId: usuario ? usuario.id : 0, 
    valorLiquido: valorLiquido.toFixed(2), 
    valorBruto: valorBruto.toFixed(2), 
    taxaMinha: taxaElite.toFixed(2), 
    taxaApi: taxaApi.toFixed(2), 
    descricao: description || (isDeposit ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
    status: dados.transactionState ? dados.transactionState.toLowerCase() : (isDeposit ? 'pendente' : 'aprovado'),
    tipo: isDeposit ? 'deposito' : 'saque',
    metodo: "PIX",
    criadoEm: dados.createdAt || new Date().toISOString()
};
```

};

// ==========================================
// 🧪 BANCO DE DADOS (COM ESTATÍSTICAS)
// ==========================================
const db = {
users: [
{ id: 1, email: ‘admin@pay.com’, password: ‘admin’, status: ‘ATIVO’, name: ‘Administrador’, role: ‘admin’, saldoCents: 0, daily_stats: { transactionCount: 0, totalReceived: 0 } },
{ id: 2, email: ‘cliente@teste.com’, password: ‘123’, status: ‘ATIVO’, name: ‘Cliente Teste’, cpf: ‘00000000000’, role: ‘user’, saldoCents: 50000, daily_stats: { transactionCount: 2, totalReceived: 150000 } },
],
transactions: [
{ id: “1”, userId: 2, valorLiquido: 150.00, valorBruto: 150.00, taxaMinha: 6.50, taxaApi: 0.50, descricao: “Depósito Inicial”, status: “aprovado”, tipo: “deposito”, metodo: “PIX”, criadoEm: new Date().toISOString() },
{ id: “2”, userId: 2, valorLiquido: 50.00, valorBruto: 50.00, taxaMinha: 1.00, taxaApi: 0, descricao: “Saque Elite Pay”, status: “aprovado”, tipo: “saque”, metodo: “PIX”, criadoEm: new Date().toISOString() }
],
credentials: {},
allowedIps: []
};

// Middleware de Autenticação
const checkAuth = (req, res, next) => {
req.user = getUserFromToken(req);

```
if (req.user && req.user.status === 'ATIVO') {
    return next();
}

console.log('🚫 REQUISIÇÃO BLOQUEADA: 401 Unauthorized');
return res.status(401).json({ error: 'Token inválido ou sessão expirada' });
```

};

// ==========================================
// 🚀 ROTAS DE LOGIN & CADASTRO
// ==========================================
const authRoutes = express.Router();

authRoutes.post(’/login’, (req, res) => {
const { email, senha, password } = req.body;
const pass = senha || password;
const ipAtual = getIp(req);

```
if (email === ADMIN_EMAIL) {
    if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
    if (ipAtual !== IP_SEGURO_ADMIN) {
        return res.status(403).json({ error: 'IP não autorizado para Admin', ip_detectado: ipAtual });
    }
    const adminUser = db.users.find(u => u.role === 'admin');
    return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
}

const user = db.users.find(u => u.email === email && (u.password === pass));

if (!user) return res.status(401).json({ error: 'Login incorreto' });
if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Sua conta está pendente de aprovação pelo administrador.' });

res.status(200).json({ token: 'TOKEN_' + user.id, user });
```

});

authRoutes.post(’/register’, (req, res) => {
const { email, name, password, cpf } = req.body;
const newUser = {
id: db.users.length + 1,
email, name, password, cpf,
status: ‘PENDENTE’, role: ‘user’,
saldoCents: 0,
daily_stats: { transactionCount: 0, totalReceived: 0 }
};
db.users.push(newUser);
res.status(201).json({ message: ‘Cadastro realizado! Aguarde aprovação.’, user: newUser });
});

authRoutes.get(’/me’, checkAuth, (req, res) => {
if(req.user) res.json(req.user);
else res.status(401).json({error: ‘Sessão expirada’});
});
app.use(’/api/auth’, authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (INTEGRAÇÃO REAL MISTICPAY)
// ==========================================
const txRoutes = express.Router();

// 1. CRIAR PIX (RECEBER) - 🔥 FUNÇÃO CORRIGIDA
txRoutes.post(’/create’, checkAuth, async (req, res) => {
const { amount, description } = req.body;
const user = req.user;

```
if (!user) return res.status(401).json({ error: 'Login necessário' });

const amountFloat = Number(amount);
const transactionId = `tx_${Date.now()}_${user.id}`;

const payerDocument = user.cpf || '00000000000';

const requestBody = {
    amount: amountFloat,
    description: description || 'Depósito Elite Pay',
    payerName: user.name || 'Cliente Elite Pay', 
    payerDocument: payerDocument, 
    transactionId: transactionId,
};

console.log(`➡️ REQ MisticPay (create): ${JSON.stringify(requestBody)}`);

try {
    const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
        body: JSON.stringify(requestBody)
    });

    const responseText = await misticResponse.text();
    let data;
    try {
        data = JSON.parse(responseText);
    } catch (e) {
        console.error('❌ MISTICPAY NÃO RETORNOU JSON VÁLIDO. TEXTO:', responseText);
        return res.status(500).json({ error: 'Erro de formatação na API MisticPay. O Backend recebeu uma resposta não-JSON.', rawResponse: responseText });
    }
    
    // Se a resposta HTTP não for 2xx (Sucesso)
    if (!misticResponse.ok) {
        console.error(`❌ Erro MisticPay [Status ${misticResponse.status}]:`, data);
        return res.status(misticResponse.status).json({ 
            error: data.message || data.error || 'Erro na API MisticPay. Verifique os logs.', 
            details: data
        });
    }
    
    // 🔥 CORREÇÃO: LOG COMPLETO DA RESPOSTA PARA DEBUG
    console.log('✅ RESPOSTA COMPLETA DA MISTICPAY:', JSON.stringify(data, null, 2));
    
    // 🔥 CORREÇÃO: BUSCAR OS DADOS EM TODOS OS POSSÍVEIS FORMATOS
    const qrcodeUrl = data.qrcodeUrl || data.qrCodeUrl || data.qrcode_url || data.qrCode || 
                      data.data?.qrcodeUrl || data.data?.qrCodeUrl || data.data?.qrcode_url || 
                      data.response?.qrcodeUrl || data.response?.qrCodeUrl || null;
    
    const copyPaste = data.copyPaste || data.copy_paste || data.pixCopyPaste || data.pix_copy_paste || 
                     data.qrCodeText || data.qrcode_text || data.emv || data.brCode || 
                     data.data?.copyPaste || data.data?.copy_paste || data.data?.pixCopyPaste ||
                     data.response?.copyPaste || data.response?.copy_paste || null;

    console.log('🔍 QR CODE EXTRAÍDO:', qrcodeUrl);
    console.log('🔍 COPIA E COLA EXTRAÍDO:', copyPaste);
    
    // ⚠️ SE NÃO ENCONTROU OS DADOS, RETORNA ERRO MAS MOSTRA A ESTRUTURA
    if (!qrcodeUrl || !copyPaste) {
         console.error('❌ CAMPOS FALTANDO. Estrutura recebida:', Object.keys(data));
         return res.status(500).json({ 
             error: 'Transação criada, mas sem dados de QR Code. Verifique o status na MisticPay.', 
             estruturaRecebida: Object.keys(data),
             dadosCompletos: data 
         });
    }

    // ✅ SUCESSO: SALVA A TRANSAÇÃO E RETORNA OS DADOS
    const novaTx = formatarTransacao(
        { ...data, transactionState: 'PENDENTE', amount: amountFloat, transactionId: transactionId, createdAt: new Date().toISOString() }, 
        'DEPOSITO', user, getIp(req), description
    );
    db.transactions.unshift(novaTx);
    
    // RETORNA EXATAMENTE O QUE O FRONT-END ESPERA
    res.json({
        qrcodeUrl: qrcodeUrl, 
        copyPaste: copyPaste,
        data: novaTx 
    });

} catch (error) {
    console.error('❌ Erro de conexão/rede:', error);
    res.status(500).json({ error: 'Erro interno ao tentar gerar PIX (Falha de rede/DNS)' });
}
```

});

// 2. SAQUE (TRANSFERIR)
txRoutes.post(’/withdraw’, checkAuth, async (req, res) => {
const { amount, pixKey, pixKeyType, description } = req.body;
const user = req.user;

```
const amountFloat = Number(amount);
const txFee = 1.00;
const totalDebit = amountFloat + txFee;
const transactionId = `out_${Date.now()}_${user.id}`;

if (user.saldoCents < totalDebit * 100) {
    return res.status(402).json({ error: 'Saldo insuficiente para saque' });
}

const requestBody = {
    amount: amountFloat,
    pixKey: pixKey,
    pixKeyType: pixKeyType,
    description: description || 'Saque Elite Pay',
    transactionId: transactionId,
};

try {
    const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/withdraw`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
        body: JSON.stringify(requestBody)
    });

    const responseText = await misticResponse.text();
    let data;
    try {
        data = JSON.parse(responseText);
    } catch (e) {
        console.error('❌ MISTICPAY SAQUE NÃO RETORNOU JSON VÁLIDO. TEXTO:', responseText);
        return res.status(500).json({ error: 'Erro de formatação na API MisticPay Saque.', rawResponse: responseText });
    }
    
    if (!misticResponse.ok) {
        console.error(`❌ Erro MisticPay Saque [Status ${misticResponse.status}]:`, data);
        return res.status(misticResponse.status).json({ 
            error: data.message || data.error || 'Erro na API de Saque MisticPay. Verifique os logs.', 
            details: data
        });
    }
    
    // ✅ SUCESSO
    user.saldoCents -= totalDebit * 100;
    
    const novaTx = formatarTransacao(
        { ...data, transactionState: 'COMPLETO', amount: amountFloat, transactionId: transactionId, createdAt: new Date().toISOString() }, 
        'RETIRADA', user, getIp(req), description
    );
    db.transactions.unshift(novaTx);
    
    user.daily_stats = { transactionCount: 0, totalReceived: 0 }; 

    res.json({ success: true, message: 'Saque realizado', transaction: novaTx });

} catch (error) {
    console.error('❌ Erro de conexão no saque:', error);
    res.status(500).json({ error: 'Erro interno ao tentar realizar saque (Falha de rede/DNS)' });
}
```

});

// 3. LISTAR TRANSAÇÕES
txRoutes.get(’/’, checkAuth, (req, res) => {
const user = req.user;

```
if (user.role === 'admin') {
    return res.json({ success: true, transactions: db.transactions });
}

const minhasTransacoes = db.transactions.filter(tx => tx.userId === user.id);
res.json({ success: true, transactions: minhasTransacoes });
```

});

app.use(’/api/transactions’, txRoutes);

// ==========================================
// 🔑 ROTAS DE CREDENCIAIS (MANUTENÇÃO)
// ==========================================
const credRoutes = express.Router();

credRoutes.get(’/’, checkAuth, (req, res) => {
const userId = req.user.id;
res.json(db.credentials[userId] || { hasCredentials: false });
});

credRoutes.post(’/generate’, checkAuth, (req, res) => {
const userId = req.user.id;

```
const newCreds = {
    hasCredentials: true,
    clientId: 'live_' + Math.random().toString(36).substr(2, 16),
    clientSecret: 'sk_' + Math.random().toString(36).substr(2, 32),
    createdAt: new Date().toISOString()
};
db.credentials[userId] = newCreds;
res.json(newCreds);
```

});

credRoutes.delete(’/’, checkAuth, (req, res) => {
delete db.credentials[req.user.id];
res.json({ success: true });
});

// IPs Permitidos
credRoutes.get(’/ips’, checkAuth, (req, res) => res.json({ ips: db.allowedIps }));
credRoutes.post(’/ips’, checkAuth, (req, res) => {
const newIp = { id: Math.random(), ip: req.body.ip, criado_em: new Date().toISOString() };
db.allowedIps.push(newIp);
res.json(newIp);
});
credRoutes.delete(’/ips/:id’, checkAuth, (req, res) => {
db.allowedIps = db.allowedIps.filter(i => i.id != req.params.id);
res.json({ success: true });
});
app.use(’/api/credentials’, credRoutes);

// ==========================================
// 👑 ROTAS DO PAINEL ADMIN (GESTÃO DE USUÁRIOS)
// ==========================================

app.get(’/api/users’, checkAuth, (req, res) => {
if (req.user.role !== ‘admin’) return res.status(403).json({ error: ‘Acesso negado’ });
res.json(db.users);
});

app.put(’/api/users/:id/status’, checkAuth, (req, res) => {
if (req.user.role !== ‘admin’) return res.status(403).json({ error: ‘Acesso negado’ });
const user = db.users.find(u => u.id == req.params.id);
if (user) {
user.status = req.body.status;
res.json({ success: true });
} else {
res.status(404).json({ error: ‘Usuário não encontrado’ });
}
});

app.get(’/api/logs’, checkAuth, (req, res) => {
if (req.user.role !== ‘admin’) return res.status(403).json({ error: ‘Acesso negado’ });
res.json([]);
});

// Inicialização
app.listen(PORT, () => {
console.log(`✅ SERVIDOR ELITE PAY RODANDO NA PORTA ${PORT}`);
console.log(`🔒 IP ADMIN SEGURO: ${IP_SEGURO_ADMIN}`);
console.log(`✨ INTEGRAÇÃO MISTICPAY: ATIVA`);
});
