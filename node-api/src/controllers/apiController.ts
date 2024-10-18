import { Request, Response } from 'express';
import { User } from '../models/User';
import nodemailer, { SendMailOptions } from 'nodemailer';
import { Jwt } from 'jsonwebtoken';
const bcrypt = require('bcrypt');

const generateRandomPassword = (length = 8) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        password += characters[randomIndex];
    }
    return password;
};

export const register = async (req: Request, res: Response) => {

    const { email, password, name, discipline } = req.body;

    if (email && password && name && discipline) {
        try {
            let hasUser = await User.findOne({ where: { email } });

            if (!hasUser) {

                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(password, saltRounds);
                
                let newUser = await User.create({
                    email,
                    password: hashedPassword,
                    name,
                    discipline
                });

                res.status(201).json({ message: 'Usuário cadastrado com sucesso.', newUser });
            } else {

                res.status(400).json({ error: 'Usuário já existe.' });
            }
        } catch (error) {
            console.error('Erro ao cadastrar usuário:', error);
            res.status(500).json({ error: 'Erro interno ao processar o registro.' });
        }
    } else {
        res.status(400).json({ error: 'E-mail, senha, nome e/ou disciplina não fornecidos' });
    }
};

    export const login = async (req: Request, res: Response) => {
        const { email, password } = req.body;
    
        if (email && password) {
            try {
                let user = await User.findOne({ where: { email } });
    
                if (user && await bcrypt.compare(password, user.password)) {
                    res.json({ status: true });
                } else {
                    res.status(401).json({ status: false, error: 'Credenciais inválidas.' });
                }
            } catch (error) {
                console.error('Erro ao fazer login:', error);
                res.status(500).json({ error: 'Erro interno ao processar o login.' });
            }
        } else {
            res.status(400).json({ error: 'E-mail e senha não fornecidos.' });
        }
    };

export const listAll = async (req: Request, res: Response) => {
    try {
        let users = await User.findAll();
        res.json({ users });
    } catch (error) {
        console.error('Erro ao listar usuários:', error);
        res.status(500).json({ error: 'Erro interno ao listar usuários.' });
    }
};


export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.params;

    try {
        const hasUser = await User.findOne({ where: { email } });

        if (!hasUser) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        const randomPassword = Math.random().toString(36).slice(-8);
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(randomPassword, saltRounds);

        hasUser.password = hashedPassword;
        await hasUser.save();
    
        const transporter = nodemailer.createTransport({
            host: 'sandbox.smtp.mailtrap.io',
            port: 2525,
            auth: {
                user: '3c06f9dbdde467',
                pass: 'b338ed92a62e61',
            },
        });

        const mailOptions = {
            from: 'seu-email@dominio.com',
            to: email,
            subject: 'Recuperação de senha',
            text: `Sua nova senha é: ${randomPassword}`, 
        };
        
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Erro ao enviar o e-mail:', error);
                res.status(500).json({ error: 'Erro ao enviar e-mail de recuperação de senha.' });
            } else {
                console.log('E-mail enviado:', info.response);
                res.status(200).json({ message: 'Nova senha enviada para o seu e-mail.' });
            }
        });
    
    } catch (error) {
        console.error('Erro ao recuperar a sennha:', error);
        res.status(500).json({ error: 'Erro interno ao processar a recuperação de senha.' });
    } 
}