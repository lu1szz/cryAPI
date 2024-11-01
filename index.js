const express = require("express");
const crypto = require("crypto");
const dotenv = require("dotenv");
const cors = require("cors");

// Carrega as variáveis de ambiente
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const API_KEY = "abcdefg123456789"; // Defina sua chave de API aqui
const algorithm = "aes-256-ecb"; // Use ECB mode (não recomendado para dados sensíveis)

const keys = {
    1: crypto.randomBytes(32),
    2: crypto.randomBytes(32),
    3: crypto.randomBytes(32),
    4: crypto.randomBytes(32),
    5: crypto.randomBytes(32),
    6: crypto.randomBytes(32),
    7: crypto.randomBytes(32),
    8: crypto.randomBytes(32),
    9: crypto.randomBytes(32),
    10: crypto.randomBytes(32),
};

// Middleware para verificar a chave de API
function authenticate(req, res, next) {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey || apiKey !== API_KEY) {
        return res
            .status(403)
            .json({ error: "Acesso negado: chave de API inválida." });
    }
    next();
}

function encryptMessage(message, keyName) {
    const key = keys[keyName];
    const cipher = crypto.createCipheriv(algorithm, key, null);

    let encrypted = cipher.update(message, "utf-8", "hex");
    encrypted += cipher.final("hex");

    return {
        encryptedData: encrypted,
        key: key.toString("hex"), // Retornando a chave em formato hexadecimal
    };
}

function decryptMessage(encryptedData, keyName) {
    const key = keys[keyName];
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key), null);

    let decrypted = decipher.update(encryptedData, "hex", "utf-8");
    decrypted += decipher.final("utf-8");

    return decrypted;
}

// Rota para criptografar a mensagem
app.post("/encrypt", authenticate, (req, res) => {
    const { message, keyName } = req.body;
    if (!message || !keyName || !keys[keyName]) {
        return res
            .status(400)
            .json({ error: "Mensagem e chave são obrigatórias" });
    }

    const encrypted = encryptMessage(message, keyName);
    res.json(encrypted);
});

// Rota para descriptografar a mensagem
app.post("/decrypt", authenticate, (req, res) => {
    const { encryptedData, keyName } = req.body;
    if (!encryptedData || !keyName || !keys[keyName]) {
        return res
            .status(400)
            .json({ error: "Dados criptografados e chave são obrigatórios" });
    }

    try {
        const decryptedMessage = decryptMessage(encryptedData, keyName);
        res.json({ decryptedMessage });
    } catch (error) {
        res.status(500).json({ error: "Falha na descriptografia" });
    }
});

// Servidor ouvindo na porta 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
